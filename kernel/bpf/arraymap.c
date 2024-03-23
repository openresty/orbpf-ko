/* Copyright (C) by OpenResty Inc. All rights reserved. */



#include <linux/orbpf_conf.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <uapi/linux/btf.h>
#include <linux/rcupdate_trace.h>

#include "map_in_map.h"
#include <linux/orbpf_config_begin.h>  

#define ARRAY_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_ACCESS_MASK | \
	 BPF_F_PRESERVE_ELEMS | BPF_F_INNER_MAP)

static void bpf_array_free_percpu(struct bpf_array *array)
{
	int i;

	for (i = 0; i < array->map.max_entries; i++) {
		free_percpu(array->pptrs[i]);
		cond_resched();
	}
}

static int bpf_array_alloc_percpu(struct bpf_array *array)
{
	void __percpu *ptr;
	int i;

	for (i = 0; i < array->map.max_entries; i++) {
		ptr = bpf_map_alloc_percpu(&array->map, array->elem_size, 8,
					   GFP_USER | __GFP_NOWARN);
		if (!ptr) {
			bpf_array_free_percpu(array);
			return -ENOMEM;
		}
		array->pptrs[i] = ptr;
		cond_resched();
	}

	return 0;
}

 
int array_map_alloc_check(union bpf_attr *attr)
{
	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	int numa_node = bpf_map_attr_numa_node(attr);

	

	 
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size == 0 ||
	    attr->map_flags & ~ARRAY_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags) ||
	    (percpu && numa_node != NUMA_NO_NODE))
	{
		
		return -EINVAL;
	}

	if (attr->map_type != BPF_MAP_TYPE_ARRAY &&
	    attr->map_flags & (BPF_F_MMAPABLE | BPF_F_INNER_MAP))
	{
		
		return -EINVAL;
	}

	if (attr->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY &&
	    attr->map_flags & BPF_F_PRESERVE_ELEMS)
	{
		
		return -EINVAL;
	}

	if (attr->value_size > KMALLOC_MAX_SIZE) {
		


		
		return -E2BIG;
	}

	return 0;
}

static struct bpf_map *array_map_alloc(union bpf_attr *attr)
{
	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	int numa_node = bpf_map_attr_numa_node(attr);
	u32 elem_size, index_mask, max_entries;
	bool bypass_spec_v1 = true;
	u64 array_size, mask64;
	struct bpf_array *array = NULL;

	elem_size = round_up(attr->value_size, 8);

	max_entries = attr->max_entries;

	



	mask64 = fls_long(max_entries - 1);
	mask64 = 1ULL << mask64;
	mask64 -= 1;

	index_mask = mask64;
	if (!bypass_spec_v1) {
		


		max_entries = index_mask + 1;
		 
		if (max_entries < attr->max_entries)
			return ERR_PTR(-E2BIG);
	}

	array_size = sizeof(*array);
	if (percpu) {
		array_size += (u64) max_entries * sizeof(void *);
	} else {
		


		if (attr->map_flags & BPF_F_MMAPABLE) {
			array_size = PAGE_ALIGN(array_size);
			array_size += PAGE_ALIGN((u64) max_entries * elem_size);
		} else {
			array_size += (u64) max_entries * elem_size;
		}
	}

	 
	if (attr->map_flags & BPF_F_MMAPABLE) {
#if 1
		void *data;

		 
		data = bpf_map_area_mmapable_alloc(array_size, numa_node);
		if (!data)
			return ERR_PTR(-ENOMEM);
		array = data + PAGE_ALIGN(sizeof(struct bpf_array))
			- offsetof(struct bpf_array, value);


#endif
	} else {
		array = bpf_map_area_alloc(array_size, numa_node);
	}
	if (!array)
		return ERR_PTR(-ENOMEM);
	array->index_mask = index_mask;
	

	 
	bpf_map_init_from_attr(&array->map, attr);
	array->elem_size = elem_size;

	if (percpu && bpf_array_alloc_percpu(array)) {
		bpf_map_area_free(array);
		return ERR_PTR(-ENOMEM);
	}

	return &array->map;
}

 
static void *array_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	return array->value + array->elem_size * (index & array->index_mask);
}

int array_map_direct_value_addr(const struct bpf_map *map, u64 *imm, u32 off)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);

	if (map->max_entries != 1)
		return -ENOTSUPP;
	if (off >= map->value_size)
		return -EINVAL;

	*imm = (unsigned long)array->value;
	return 0;
}

#if 1
static int array_map_direct_value_meta(const struct bpf_map *map, u64 imm,
				       u32 *off)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u64 base = (unsigned long)array->value;
	u64 range = array->elem_size;

	if (map->max_entries != 1)
		return -ENOTSUPP;
	if (imm < base || imm >= base + range)
		return -ENOENT;

	*off = imm - base;
	return 0;
}
#endif

 
static


#if 1
int
#endif
array_map_gen_lookup(struct bpf_map *map, struct bpf_insn *insn_buf)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_insn *insn = insn_buf;
	u32 elem_size = round_up(map->value_size, 8);
	const int ret = BPF_REG_0;
	const int map_ptr = BPF_REG_1;
	const int index = BPF_REG_2;

	if (map->map_flags & BPF_F_INNER_MAP)
		return -EOPNOTSUPP;

	*insn++ = BPF_ALU64_IMM(BPF_ADD, map_ptr, offsetof(struct bpf_array, value));
	*insn++ = BPF_LDX_MEM(BPF_W, ret, index, 0);
	if (0  ) {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 4);
		*insn++ = BPF_ALU32_IMM(BPF_AND, ret, array->index_mask);
	} else {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 3);
	}

	if (is_power_of_2(elem_size)) {
		*insn++ = BPF_ALU64_IMM(BPF_LSH, ret, ilog2(elem_size));
	} else {
		*insn++ = BPF_ALU64_IMM(BPF_MUL, ret, elem_size);
	}
	*insn++ = BPF_ALU64_REG(BPF_ADD, ret, map_ptr);
	*insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
	*insn++ = BPF_MOV64_IMM(ret, 0);
	return insn - insn_buf;
}

 
static void *percpu_array_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	return this_cpu_ptr(array->pptrs[index & array->index_mask]);
}

int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	void __percpu *pptr;
	int cpu, off = 0;
	u32 size;

	if (unlikely(index >= array->map.max_entries))
		return -ENOENT;

	



	size = round_up(map->value_size, 8);
	rcu_read_lock();
	pptr = array->pptrs[index & array->index_mask];
	for_each_possible_cpu(cpu) {
		bpf_long_memcpy(value + off, per_cpu_ptr(pptr, cpu), size);
		off += size;
	}
	rcu_read_unlock();
	return 0;
}

 
static int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= array->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == array->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

 
static int array_map_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	char *val;

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		 
		return -EINVAL;

	if (unlikely(index >= array->map.max_entries))
		 
		return -E2BIG;

	if (unlikely(map_flags & BPF_NOEXIST))
		 
		return -EEXIST;

	if (unlikely((map_flags & BPF_F_LOCK) &&
		     !orbpf_map_value_has_spin_lock(map)))
		return -EINVAL;

	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		memcpy(this_cpu_ptr(array->pptrs[index & array->index_mask]),
		       value, map->value_size);
	} else {
		val = array->value +
			array->elem_size * (index & array->index_mask);
		if (map_flags & BPF_F_LOCK)
			orbpf_copy_map_value_locked(map, val, value, false);
		else
			orbpf_copy_map_value(map, val, value);
	}
	return 0;
}

int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
			    u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	void __percpu *pptr;
	int cpu, off = 0;
	u32 size;

	if (unlikely(map_flags > BPF_EXIST))
		 
		return -EINVAL;

	if (unlikely(index >= array->map.max_entries))
		 
		return -E2BIG;

	if (unlikely(map_flags == BPF_NOEXIST))
		 
		return -EEXIST;

	





	size = round_up(map->value_size, 8);
	rcu_read_lock();
	pptr = array->pptrs[index & array->index_mask];
	for_each_possible_cpu(cpu) {
		bpf_long_memcpy(per_cpu_ptr(pptr, cpu), value + off, size);
		off += size;
	}
	rcu_read_unlock();
	return 0;
}

 
static int array_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;
}

static void *array_map_vmalloc_addr(struct bpf_array *array)
{
	return (void *)round_down((unsigned long)array, PAGE_SIZE);
}

 
static void array_map_free(struct bpf_map *map)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);

	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		bpf_array_free_percpu(array);

	if (array->map.map_flags & BPF_F_MMAPABLE)
		bpf_map_area_free(array_map_vmalloc_addr(array));
	else
		bpf_map_area_free(array);
}

static void array_map_seq_show_elem(struct bpf_map *map, void *key,
				    struct seq_file *m)
{
	void *value;

	rcu_read_lock();

	value = array_map_lookup_elem(map, key);
	if (!value) {
		rcu_read_unlock();
		return;
	}

	if (map->btf_key_type_id)
		seq_printf(m, "%u: ", *(u32 *)key);
	btf_type_seq_show(map->btf, map->btf_value_type_id, value, m);
	seq_puts(m, "\n");

	rcu_read_unlock();
}

static void percpu_array_map_seq_show_elem(struct bpf_map *map, void *key,
					   struct seq_file *m)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	void __percpu *pptr;
	int cpu;

	rcu_read_lock();

	seq_printf(m, "%u: {\n", *(u32 *)key);
	pptr = array->pptrs[index & array->index_mask];
	for_each_possible_cpu(cpu) {
		seq_printf(m, "\tcpu%d: ", cpu);
		btf_type_seq_show(map->btf, map->btf_value_type_id,
				  per_cpu_ptr(pptr, cpu), m);
		seq_puts(m, "\n");
	}
	seq_puts(m, "}\n");

	rcu_read_unlock();
}

static int array_map_check_btf(const struct bpf_map *map,
			       const struct btf *btf,
			       const struct btf_type *key_type,
			       const struct btf_type *value_type)
{
	u32 int_data;

	 
	if (btf_type_is_void(key_type)) {
		if (map->map_type != BPF_MAP_TYPE_ARRAY ||
		    map->max_entries != 1)
			return -EINVAL;

		if (BTF_INFO_KIND(value_type->info) != BTF_KIND_DATASEC)
			return -EINVAL;

		return 0;
	}

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	


	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}

#if 1
static int array_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	pgoff_t pgoff = PAGE_ALIGN(sizeof(*array)) >> PAGE_SHIFT;

	if (!(map->map_flags & BPF_F_MMAPABLE))
		return -EINVAL;

	if (vma->vm_pgoff * PAGE_SIZE + (vma->vm_end - vma->vm_start) >
	    PAGE_ALIGN((u64)array->map.max_entries * array->elem_size))
		return -EINVAL;

	return remap_vmalloc_range(vma, array_map_vmalloc_addr(array),
				   vma->vm_pgoff + pgoff);
}
#endif

#if 1
static bool array_map_meta_equal(const struct bpf_map *meta0,
				 const struct bpf_map *meta1)
{
	if (!bpf_map_meta_equal(meta0, meta1))
		return false;
	return meta0->map_flags & BPF_F_INNER_MAP ? true :
	       meta0->max_entries == meta1->max_entries;
}
#endif

#if 1
struct bpf_iter_seq_array_map_info {
	struct bpf_map *map;
	void *percpu_value_buf;
	u32 index;
};

static void *bpf_array_map_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_array_map_info *info = seq->private;
	struct bpf_map *map = info->map;
	struct bpf_array *array;
	u32 index;

	if (info->index >= map->max_entries)
		return NULL;

	if (*pos == 0)
		++*pos;
	array = container_of(map, struct bpf_array, map);
	index = info->index & array->index_mask;
	if (info->percpu_value_buf)
	       return array->pptrs[index];
	return array->value + array->elem_size * index;
}

static void *bpf_array_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_array_map_info *info = seq->private;
	struct bpf_map *map = info->map;
	struct bpf_array *array;
	u32 index;

	++*pos;
	++info->index;
	if (info->index >= map->max_entries)
		return NULL;

	array = container_of(map, struct bpf_array, map);
	index = info->index & array->index_mask;
	if (info->percpu_value_buf)
	       return array->pptrs[index];
	return array->value + array->elem_size * index;
}

static int __bpf_array_map_seq_show(struct seq_file *seq, void *v)
{
	struct bpf_iter_seq_array_map_info *info = seq->private;
	struct bpf_iter__bpf_map_elem ctx = {};
	struct bpf_map *map = info->map;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;
	int off = 0, cpu = 0;
	void __percpu **pptr;
	u32 size;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, v == NULL);
	if (!prog)
		return 0;

	ctx.meta = &meta;
	ctx.map = info->map;
	if (v) {
		ctx.key = &info->index;

		if (!info->percpu_value_buf) {
			ctx.value = v;
		} else {
			pptr = v;
			size = round_up(map->value_size, 8);
			for_each_possible_cpu(cpu) {
				bpf_long_memcpy(info->percpu_value_buf + off,
						per_cpu_ptr(pptr, cpu),
						size);
				off += size;
			}
			ctx.value = info->percpu_value_buf;
		}
	}

	return bpf_iter_run_prog(prog, &ctx);
}

static int bpf_array_map_seq_show(struct seq_file *seq, void *v)
{
	return __bpf_array_map_seq_show(seq, v);
}

static void bpf_array_map_seq_stop(struct seq_file *seq, void *v)
{
	if (!v)
		(void)__bpf_array_map_seq_show(seq, NULL);
}

static int bpf_iter_init_array_map(void *priv_data,
				   struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_array_map_info *seq_info = priv_data;
	struct bpf_map *map = aux->map;
	void *value_buf;
	u32 buf_size;

	if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		buf_size = round_up(map->value_size, 8) * num_possible_cpus();
		value_buf = kmalloc(buf_size, GFP_USER | __GFP_NOWARN);
		if (!value_buf)
			return -ENOMEM;

		seq_info->percpu_value_buf = value_buf;
	}

	seq_info->map = map;
	return 0;
}

static void bpf_iter_fini_array_map(void *priv_data)
{
	struct bpf_iter_seq_array_map_info *seq_info = priv_data;

	kfree(seq_info->percpu_value_buf);
}

static const struct seq_operations bpf_array_map_seq_ops = {
	.start	= bpf_array_map_seq_start,
	.next	= bpf_array_map_seq_next,
	.stop	= bpf_array_map_seq_stop,
	.show	= bpf_array_map_seq_show,
};

static const struct bpf_iter_seq_info iter_seq_info = {
	.seq_ops		= &bpf_array_map_seq_ops,
	.init_seq_private	= bpf_iter_init_array_map,
	.fini_seq_private	= bpf_iter_fini_array_map,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_array_map_info),
};

static int bpf_for_each_array_elem(struct bpf_map *map, void *callback_fn,
				   void *callback_ctx, u64 flags)
{
	u32 i, key, num_elems = 0;
	struct bpf_array *array;
	bool is_percpu;
	u64 ret = 0;
	void *val;

	if (flags != 0)
		return -EINVAL;

	is_percpu = map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	array = container_of(map, struct bpf_array, map);
	if (is_percpu)
		migrate_disable();
	for (i = 0; i < map->max_entries; i++) {
		if (is_percpu)
			val = this_cpu_ptr(array->pptrs[i]);
		else
			val = array->value + array->elem_size * i;
		num_elems++;
		key = i;
		ret = BPF_CAST_CALL(callback_fn)((u64)(long)map,
					(u64)(long)&key, (u64)(long)val,
					(u64)(long)callback_ctx, 0);
		 
		if (ret)
			break;
	}

	if (is_percpu)
		migrate_enable();
	return num_elems;
}
#endif


const struct bpf_map_ops array_map_ops = {
#if 1
	.map_meta_equal = array_map_meta_equal,
#endif
	.map_alloc_check = array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = array_map_lookup_elem,
	.map_update_elem = array_map_update_elem,
	.map_delete_elem = array_map_delete_elem,
	.map_gen_lookup = array_map_gen_lookup,
#if 1
	.map_direct_value_addr = array_map_direct_value_addr,
	.map_direct_value_meta = array_map_direct_value_meta,
#endif
#if 1
	.map_mmap = array_map_mmap,
#endif
	.map_seq_show_elem = array_map_seq_show_elem,
	.map_check_btf = array_map_check_btf,
#if 1
	.map_lookup_batch = generic_map_lookup_batch,
	.map_update_batch = generic_map_update_batch,
#endif
#if 1
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_array_elem,
#endif




#if 1
	.iter_seq_info = &iter_seq_info,
#endif
};


const struct bpf_map_ops percpu_array_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = percpu_array_map_lookup_elem,
	.map_update_elem = array_map_update_elem,
	.map_delete_elem = array_map_delete_elem,
	.map_seq_show_elem = percpu_array_map_seq_show_elem,
	.map_check_btf = array_map_check_btf,
#if 1
	.map_lookup_batch = generic_map_lookup_batch,
	.map_update_batch = generic_map_update_batch,
#endif
#if 1
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_array_elem,
#endif




#if 1
	.iter_seq_info = &iter_seq_info,
#endif
};

static int fd_array_map_alloc_check(union bpf_attr *attr)
{
	 
	if (attr->value_size != sizeof(u32))
		return -EINVAL;
	 
	if (attr->map_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG))
		return -EINVAL;
	return array_map_alloc_check(attr);
}

static void fd_array_map_free(struct bpf_map *map)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	int i;

	 
	for (i = 0; i < array->map.max_entries; i++)
		BUG_ON(array->ptrs[i] != NULL);

	bpf_map_area_free(array);
}

static void *fd_array_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

 
int bpf_fd_array_map_lookup_elem(struct bpf_map *map, void *key, u32 *value)
{
	void **elem, *ptr;
	int ret =  0;

	if (!map->ops->map_fd_sys_lookup_elem)
		return -ENOTSUPP;

	rcu_read_lock();
	elem = array_map_lookup_elem(map, key);
	if (elem && (ptr = READ_ONCE(*elem)))
		*value = map->ops->map_fd_sys_lookup_elem(ptr);
	else
		ret = -ENOENT;
	rcu_read_unlock();

	return ret;
}

 
int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
				 void *key, void *value, u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *new_ptr, *old_ptr;
	u32 index = *(u32 *)key, ufd;

	if (map_flags != BPF_ANY)
		return -EINVAL;

	if (index >= array->map.max_entries)
		return -E2BIG;

	ufd = *(u32 *)value;
	new_ptr = map->ops->map_fd_get_ptr(map, map_file, ufd);
	if (IS_ERR(new_ptr))
		return PTR_ERR(new_ptr);








	if (0) {
	} else {
		old_ptr = xchg(array->ptrs + index, new_ptr);
	}

	if (old_ptr)
		map->ops->map_fd_put_ptr(old_ptr);
	return 0;
}

static int fd_array_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *old_ptr;
	u32 index = *(u32 *)key;

	if (index >= array->map.max_entries)
		return -E2BIG;








	if (0) {
	} else {
		old_ptr = xchg(array->ptrs + index, NULL);
	}

	if (old_ptr) {
		map->ops->map_fd_put_ptr(old_ptr);
		return 0;
	} else {
		return -ENOENT;
	}
}

static void *prog_fd_array_get_ptr(struct bpf_map *map,
				   struct file *map_file, int fd)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_prog *prog = bpf_prog_get(fd);

	if (IS_ERR(prog))
		return prog;

	if (!bpf_prog_array_compatible(array, prog)) {
		bpf_prog_put(prog);
		return ERR_PTR(-EINVAL);
	}

	return prog;
}

static void prog_fd_array_put_ptr(void *ptr)
{
	bpf_prog_put(ptr);
}

static u32 prog_fd_array_sys_lookup_elem(void *ptr)
{
	return ((struct bpf_prog *)ptr)->aux->id;
}

 
static void bpf_fd_array_map_clear(struct bpf_map *map)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	int i;

	for (i = 0; i < array->map.max_entries; i++)
		fd_array_map_delete_elem(map, &i);
}

static void prog_array_map_seq_show_elem(struct bpf_map *map, void *key,
					 struct seq_file *m)
{
	void **elem, *ptr;
	u32 prog_id;

	rcu_read_lock();

	elem = array_map_lookup_elem(map, key);
	if (elem) {
		ptr = READ_ONCE(*elem);
		if (ptr) {
			seq_printf(m, "%u: ", *(u32 *)key);
			prog_id = prog_fd_array_sys_lookup_elem(ptr);
			btf_type_seq_show(map->btf, map->btf_value_type_id,
					  &prog_id, m);
			seq_puts(m, "\n");
		}
	}

	rcu_read_unlock();
}








































































































































































#if 1
static struct bpf_map *prog_array_map_alloc(union bpf_attr *attr)
{
	struct bpf_array_aux *aux;
	struct bpf_map *map;

	aux = kzalloc(sizeof(*aux), GFP_KERNEL_ACCOUNT);
	if (!aux)
		return ERR_PTR(-ENOMEM);







	map = array_map_alloc(attr);
	if (IS_ERR(map)) {
		kfree(aux);
		return map;
	}

	container_of(map, struct bpf_array, map)->aux = aux;
	aux->map = map;

	return map;
}

static void prog_array_map_free(struct bpf_map *map)
{
	struct bpf_array_aux *aux = container_of(map, struct bpf_array, map)->aux;








	kfree(aux);
	fd_array_map_free(map);
}
#endif







const struct bpf_map_ops prog_array_map_ops = {
	.map_alloc_check = fd_array_map_alloc_check,
#if 1
	.map_alloc = prog_array_map_alloc,
	.map_free = prog_array_map_free,



#endif





	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = fd_array_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = prog_fd_array_get_ptr,
	.map_fd_put_ptr = prog_fd_array_put_ptr,
	.map_fd_sys_lookup_elem = prog_fd_array_sys_lookup_elem,


#if 1
	.map_release_uref = bpf_fd_array_map_clear,
#endif
	.map_seq_show_elem = prog_array_map_seq_show_elem,




};

static struct bpf_event_entry *bpf_event_entry_gen(struct file *perf_file,
						   struct file *map_file)
{
	struct bpf_event_entry *ee;

	ee = kzalloc(sizeof(*ee), GFP_ATOMIC);
	if (ee) {
		ee->event = perf_file->private_data;
		ee->perf_file = perf_file;
		ee->map_file = map_file;
	}

	return ee;
}

static void __bpf_event_entry_free(struct rcu_head *rcu)
{
	struct bpf_event_entry *ee;

	ee = container_of(rcu, struct bpf_event_entry, rcu);
	fput(ee->perf_file);
	kfree(ee);
}

static void bpf_event_entry_free_rcu(struct bpf_event_entry *ee)
{
	call_rcu(&ee->rcu, __bpf_event_entry_free);
}

static void *perf_event_fd_array_get_ptr(struct bpf_map *map,
					 struct file *map_file, int fd)
{
	struct bpf_event_entry *ee;
	struct perf_event *event;
	struct file *perf_file;
	u64 value;

	perf_file = perf_event_get(fd);
	if (IS_ERR(perf_file))
		return perf_file;

	ee = ERR_PTR(-EOPNOTSUPP);
	event = perf_file->private_data;
	if (perf_event_read_local(event, &value, NULL, NULL) == -EOPNOTSUPP)
		goto err_out;

	ee = bpf_event_entry_gen(perf_file, map_file);
	if (ee)
		return ee;
	ee = ERR_PTR(-ENOMEM);
err_out:
	fput(perf_file);
	return ee;
}

static void perf_event_fd_array_put_ptr(void *ptr)
{
	bpf_event_entry_free_rcu(ptr);
}

static void perf_event_fd_array_release(struct bpf_map *map,
					struct file *map_file)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_event_entry *ee;
	int i;

	if (map->map_flags & BPF_F_PRESERVE_ELEMS)
		return;

	rcu_read_lock();
	for (i = 0; i < array->map.max_entries; i++) {
		ee = READ_ONCE(array->ptrs[i]);
		if (ee && ee->map_file == map_file)
			fd_array_map_delete_elem(map, &i);
	}
	rcu_read_unlock();
}

static void perf_event_fd_array_map_free(struct bpf_map *map)
{
	if (map->map_flags & BPF_F_PRESERVE_ELEMS)
		bpf_fd_array_map_clear(map);
	fd_array_map_free(map);
}


const struct bpf_map_ops perf_event_array_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = perf_event_fd_array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = fd_array_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = perf_event_fd_array_get_ptr,
	.map_fd_put_ptr = perf_event_fd_array_put_ptr,
	.map_release = perf_event_fd_array_release,
	.map_check_btf = map_check_no_btf,




};

#ifdef CONFIG_CGROUPS
static void *cgroup_fd_array_get_ptr(struct bpf_map *map,
				     struct file *map_file  ,
				     int fd)
{
	return cgroup_get_from_fd(fd);
}

static void cgroup_fd_array_put_ptr(void *ptr)
{
	 
	cgroup_put(ptr);
}

static void cgroup_fd_array_free(struct bpf_map *map)
{
	bpf_fd_array_map_clear(map);
	fd_array_map_free(map);
}


const struct bpf_map_ops cgroup_array_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = cgroup_fd_array_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = fd_array_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = cgroup_fd_array_get_ptr,
	.map_fd_put_ptr = cgroup_fd_array_put_ptr,
	.map_check_btf = map_check_no_btf,




};
#endif

static struct bpf_map *array_of_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map, *inner_map_meta;

	inner_map_meta = bpf_map_meta_alloc(attr->inner_map_fd);
	if (IS_ERR(inner_map_meta))
		return inner_map_meta;

	map = array_map_alloc(attr);
	if (IS_ERR(map)) {
		bpf_map_meta_free(inner_map_meta);
		return map;
	}

	map->inner_map_meta = inner_map_meta;

	return map;
}

static void array_of_map_free(struct bpf_map *map)
{
	


	bpf_map_meta_free(map->inner_map_meta);
	bpf_fd_array_map_clear(map);
	fd_array_map_free(map);
}

static void *array_of_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map = array_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}

static


#if 1
int
#endif
array_of_map_gen_lookup(struct bpf_map *map,
				   struct bpf_insn *insn_buf)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 elem_size = round_up(map->value_size, 8);
	struct bpf_insn *insn = insn_buf;
	const int ret = BPF_REG_0;
	const int map_ptr = BPF_REG_1;
	const int index = BPF_REG_2;

	*insn++ = BPF_ALU64_IMM(BPF_ADD, map_ptr, offsetof(struct bpf_array, value));
	*insn++ = BPF_LDX_MEM(BPF_W, ret, index, 0);
	if (0  ) {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 6);
		*insn++ = BPF_ALU32_IMM(BPF_AND, ret, array->index_mask);
	} else {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 5);
	}
	if (is_power_of_2(elem_size))
		*insn++ = BPF_ALU64_IMM(BPF_LSH, ret, ilog2(elem_size));
	else
		*insn++ = BPF_ALU64_IMM(BPF_MUL, ret, elem_size);
	*insn++ = BPF_ALU64_REG(BPF_ADD, ret, map_ptr);
	*insn++ = BPF_LDX_MEM(BPF_DW, ret, ret, 0);
	*insn++ = BPF_JMP_IMM(BPF_JEQ, ret, 0, 1);
	*insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
	*insn++ = BPF_MOV64_IMM(ret, 0);

	return insn - insn_buf;
}


const struct bpf_map_ops array_of_maps_map_ops = {
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_of_map_alloc,
	.map_free = array_of_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = array_of_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = bpf_map_fd_get_ptr,
	.map_fd_put_ptr = bpf_map_fd_put_ptr,
	.map_fd_sys_lookup_elem = bpf_map_fd_sys_lookup_elem,
	.map_gen_lookup = array_of_map_gen_lookup,
	.map_check_btf = map_check_no_btf,




};