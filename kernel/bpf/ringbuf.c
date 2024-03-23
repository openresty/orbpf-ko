/* Copyright (C) by OpenResty Inc. All rights reserved. */ #include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/irq_work.h>
#include <linux/slab.h>
#include <linux/filter.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/kmemleak.h>
#include <uapi/linux/btf.h>
#include <linux/orbpf_config_begin.h>  

#define RINGBUF_CREATE_FLAG_MASK (BPF_F_NUMA_NODE)

 
#define RINGBUF_PGOFF \
	(offsetof(struct bpf_ringbuf, consumer_pos) >> PAGE_SHIFT)
 
#define RINGBUF_POS_PAGES 2

#define RINGBUF_MAX_RECORD_SZ (UINT_MAX/4)







#define RINGBUF_MAX_DATA_SZ \
	(((1ULL << 24) - RINGBUF_POS_PAGES - RINGBUF_PGOFF) * PAGE_SIZE)

struct bpf_ringbuf {
	wait_queue_head_t waitq;
	struct irq_work work;
	u64 mask;
	struct page **pages;
	int nr_pages;
	spinlock_t spinlock ____cacheline_aligned_in_smp;
	




	unsigned long consumer_pos __aligned(PAGE_SIZE);
	unsigned long producer_pos __aligned(PAGE_SIZE);
	char data[] __aligned(PAGE_SIZE);
};

struct bpf_ringbuf_map {
	struct bpf_map map;
	struct bpf_ringbuf *rb;
};

 
struct bpf_ringbuf_hdr {
	u32 len;
	u32 pg_off;
};

static struct bpf_ringbuf *bpf_ringbuf_area_alloc(size_t data_sz, int numa_node)
{
	const gfp_t flags = GFP_KERNEL_ACCOUNT | __GFP_RETRY_MAYFAIL |
			    __GFP_NOWARN | __GFP_ZERO;
	int nr_meta_pages = RINGBUF_PGOFF + RINGBUF_POS_PAGES;
	int nr_data_pages = data_sz >> PAGE_SHIFT;
	int nr_pages = nr_meta_pages + nr_data_pages;
	struct page **pages, *page;
	struct bpf_ringbuf *rb;
	size_t array_size;
	int i;

	
















	array_size = (nr_meta_pages + 2 * nr_data_pages) * sizeof(*pages);
	pages = bpf_map_area_alloc(array_size, numa_node);
	if (!pages)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		page = alloc_pages_node(numa_node, flags, 0);
		if (!page) {
			nr_pages = i;
			goto err_free_pages;
		}
		pages[i] = page;
		if (i >= nr_meta_pages)
			pages[nr_data_pages + i] = page;
	}

	rb = vmap(pages, nr_meta_pages + 2 * nr_data_pages,
		  VM_MAP | VM_USERMAP, PAGE_KERNEL);
	if (rb) {
		kmemleak_not_leak(pages);
		rb->pages = pages;
		rb->nr_pages = nr_pages;
		return rb;
	}

err_free_pages:
	for (i = 0; i < nr_pages; i++)
		__free_page(pages[i]);
	kvfree(pages);
	return NULL;
}

static void bpf_ringbuf_notify(struct irq_work *work)
{
	struct bpf_ringbuf *rb = container_of(work, struct bpf_ringbuf, work);

	wake_up_all(&rb->waitq);
}

static struct bpf_ringbuf *bpf_ringbuf_alloc(size_t data_sz, int numa_node)
{
	struct bpf_ringbuf *rb;

	rb = bpf_ringbuf_area_alloc(data_sz, numa_node);
	if (!rb)
		return NULL;

	spin_lock_init(&rb->spinlock);
	init_waitqueue_head(&rb->waitq);
	init_irq_work(&rb->work, bpf_ringbuf_notify);

	rb->mask = data_sz - 1;
	rb->consumer_pos = 0;
	rb->producer_pos = 0;

	return rb;
}

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
	struct bpf_ringbuf_map *rb_map;

	if (attr->map_flags & ~RINGBUF_CREATE_FLAG_MASK)
		return ERR_PTR(-EINVAL);

	if (attr->key_size || attr->value_size ||
	    !is_power_of_2(attr->max_entries) ||
	    !PAGE_ALIGNED(attr->max_entries))
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_64BIT
	 
	if (attr->max_entries > RINGBUF_MAX_DATA_SZ)
		return ERR_PTR(-E2BIG);
#endif

	rb_map = kzalloc(sizeof(*rb_map), GFP_USER | __GFP_ACCOUNT);
	if (!rb_map)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&rb_map->map, attr);

	rb_map->rb = bpf_ringbuf_alloc(attr->max_entries, rb_map->map.numa_node);
	if (!rb_map->rb) {
		kfree(rb_map);
		return ERR_PTR(-ENOMEM);
	}

	return &rb_map->map;
}

static void bpf_ringbuf_free(struct bpf_ringbuf *rb)
{
	


	struct page **pages = rb->pages;
	int i, nr_pages = rb->nr_pages;

	vunmap(rb);
	for (i = 0; i < nr_pages; i++)
		__free_page(pages[i]);
	kvfree(pages);
}

static void ringbuf_map_free(struct bpf_map *map)
{
	struct bpf_ringbuf_map *rb_map;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);
	bpf_ringbuf_free(rb_map->rb);
	kfree(rb_map);
}

static void *ringbuf_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-ENOTSUPP);
}

static int ringbuf_map_update_elem(struct bpf_map *map, void *key, void *value,
				   u64 flags)
{
	return -ENOTSUPP;
}

static int ringbuf_map_delete_elem(struct bpf_map *map, void *key)
{
	return -ENOTSUPP;
}

static int ringbuf_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	return -ENOTSUPP;
}

#if 1
static int ringbuf_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	struct bpf_ringbuf_map *rb_map;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);

	if (vma->vm_flags & VM_WRITE) {
		 
		if (vma->vm_pgoff != 0 || vma->vm_end - vma->vm_start != PAGE_SIZE)
			return -EPERM;
	} else {
		vm_flags_clear(vma, VM_MAYWRITE);
	}
	 
	return remap_vmalloc_range(vma, rb_map->rb,
				   vma->vm_pgoff + RINGBUF_PGOFF);
}
#endif

static unsigned long ringbuf_avail_data_sz(struct bpf_ringbuf *rb)
{
	unsigned long cons_pos, prod_pos;

	cons_pos = smp_load_acquire(&rb->consumer_pos);
	prod_pos = smp_load_acquire(&rb->producer_pos);
	return prod_pos - cons_pos;
}

#if 1
static __poll_t ringbuf_map_poll(struct bpf_map *map, struct file *filp,
				 struct poll_table_struct *pts)
{
	struct bpf_ringbuf_map *rb_map;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);
	poll_wait(filp, &rb_map->rb->waitq, pts);

	if (ringbuf_avail_data_sz(rb_map->rb))
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}
#endif


const struct bpf_map_ops ringbuf_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc = ringbuf_map_alloc,
	.map_free = ringbuf_map_free,
#if 1
	.map_mmap = ringbuf_map_mmap,
#endif
#if 1
	.map_poll = ringbuf_map_poll,
#endif
	.map_lookup_elem = ringbuf_map_lookup_elem,
	.map_update_elem = ringbuf_map_update_elem,
	.map_delete_elem = ringbuf_map_delete_elem,
	.map_get_next_key = ringbuf_map_get_next_key,




};







static size_t bpf_ringbuf_rec_pg_off(struct bpf_ringbuf *rb,
				     struct bpf_ringbuf_hdr *hdr)
{
	return ((void *)hdr - (void *)rb) >> PAGE_SHIFT;
}




static struct bpf_ringbuf *
bpf_ringbuf_restore_from_rec(struct bpf_ringbuf_hdr *hdr)
{
	unsigned long addr = (unsigned long)(void *)hdr;
	unsigned long off = (unsigned long)hdr->pg_off << PAGE_SHIFT;

	return (void*)((addr & PAGE_MASK) - off);
}

static void *__bpf_ringbuf_reserve(struct bpf_ringbuf *rb, u64 size)
{
	unsigned long cons_pos, prod_pos, new_prod_pos, flags;
	u32 len, pg_off;
	struct bpf_ringbuf_hdr *hdr;

	if (unlikely(size > RINGBUF_MAX_RECORD_SZ))
		return NULL;

	len = round_up(size + BPF_RINGBUF_HDR_SZ, 8);
	if (len > rb->mask + 1)
		return NULL;

	cons_pos = smp_load_acquire(&rb->consumer_pos);

	if (in_nmi()) {
		if (!spin_trylock_irqsave(&rb->spinlock, flags))
			return NULL;
	} else {
		spin_lock_irqsave(&rb->spinlock, flags);
	}

	prod_pos = rb->producer_pos;
	new_prod_pos = prod_pos + len;

	


	if (new_prod_pos - cons_pos > rb->mask) {
		spin_unlock_irqrestore(&rb->spinlock, flags);
		return NULL;
	}

	hdr = (void *)rb->data + (prod_pos & rb->mask);
	pg_off = bpf_ringbuf_rec_pg_off(rb, hdr);
	hdr->len = size | BPF_RINGBUF_BUSY_BIT;
	hdr->pg_off = pg_off;

	 
	smp_store_release(&rb->producer_pos, new_prod_pos);

	spin_unlock_irqrestore(&rb->spinlock, flags);

	return (void *)hdr + BPF_RINGBUF_HDR_SZ;
}

BPF_CALL_3(bpf_ringbuf_reserve, struct bpf_map *, map, u64, size, u64, flags)
{
	struct bpf_ringbuf_map *rb_map;

	if (unlikely(flags))
		return 0;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);
	return (unsigned long)__bpf_ringbuf_reserve(rb_map->rb, size);
}

const struct bpf_func_proto bpf_ringbuf_reserve_proto = {
	.func		= bpf_ringbuf_reserve,
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

static void bpf_ringbuf_commit(void *sample, u64 flags, bool discard)
{
	unsigned long rec_pos, cons_pos;
	struct bpf_ringbuf_hdr *hdr;
	struct bpf_ringbuf *rb;
	u32 new_len;

	hdr = sample - BPF_RINGBUF_HDR_SZ;
	rb = bpf_ringbuf_restore_from_rec(hdr);
	new_len = hdr->len ^ BPF_RINGBUF_BUSY_BIT;
	if (discard)
		new_len |= BPF_RINGBUF_DISCARD_BIT;

	 
	xchg(&hdr->len, new_len);

	


	rec_pos = (void *)hdr - (void *)rb->data;
	cons_pos = smp_load_acquire(&rb->consumer_pos) & rb->mask;

	if (flags & BPF_RB_FORCE_WAKEUP)
		irq_work_queue(&rb->work);
	else if (cons_pos == rec_pos && !(flags & BPF_RB_NO_WAKEUP))
		irq_work_queue(&rb->work);
}

BPF_CALL_2(bpf_ringbuf_submit, void *, sample, u64, flags)
{
	bpf_ringbuf_commit(sample, flags, false  );
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_submit_proto = {
	.func		= bpf_ringbuf_submit,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_discard, void *, sample, u64, flags)
{
	bpf_ringbuf_commit(sample, flags, true  );
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_discard_proto = {
	.func		= bpf_ringbuf_discard,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_ringbuf_output, struct bpf_map *, map, void *, data, u64, size,
	   u64, flags)
{
	struct bpf_ringbuf_map *rb_map;
	void *rec;

	if (unlikely(flags & ~(BPF_RB_NO_WAKEUP | BPF_RB_FORCE_WAKEUP)))
		return -EINVAL;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);
	rec = __bpf_ringbuf_reserve(rb_map->rb, size);
	if (!rec)
		return -EAGAIN;

	memcpy(rec, data, size);
	bpf_ringbuf_commit(rec, flags, false  );
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_output_proto = {
	.func		= bpf_ringbuf_output,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_query, struct bpf_map *, map, u64, flags)
{
	struct bpf_ringbuf *rb;

	rb = container_of(map, struct bpf_ringbuf_map, map)->rb;

	switch (flags) {
	case BPF_RB_AVAIL_DATA:
		return ringbuf_avail_data_sz(rb);
	case BPF_RB_RING_SIZE:
		return rb->mask + 1;
	case BPF_RB_CONS_POS:
		return smp_load_acquire(&rb->consumer_pos);
	case BPF_RB_PROD_POS:
		return smp_load_acquire(&rb->producer_pos);
	default:
		return 0;
	}
}

const struct bpf_func_proto bpf_ringbuf_query_proto = {
	.func		= bpf_ringbuf_query,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};