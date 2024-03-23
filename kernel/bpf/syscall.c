/* Copyright (C) by OpenResty Inc. All rights reserved. */ #define DDEBUG 0



#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/bpf_lirc.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include <linux/mmzone.h>
#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/license.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/cred.h>
#include <linux/timekeeping.h>
#include <linux/ctype.h>
#include <linux/nospec.h>

#include <uapi/linux/btf.h>

#include <linux/bpf_lsm.h>
#include <linux/poll.h>
#include <linux/bpf-netns.h>
#include <linux/rcupdate_trace.h>
#include <linux/memcontrol.h>
#include <linux/orbpf_config_begin.h>  

#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_PROG_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map) || \
			IS_FD_HASH(map))

#define BPF_OBJ_FLAG_MASK   (BPF_F_RDONLY | BPF_F_WRONLY)

int __percpu *bpf_prog_active;


static DEFINE_IDR(prog_idr);
static DEFINE_SPINLOCK(prog_idr_lock);
static DEFINE_IDR(map_idr);
static DEFINE_SPINLOCK(map_idr_lock);
static DEFINE_IDR(link_idr);
static DEFINE_SPINLOCK(link_idr_lock);

int sysctl_unprivileged_bpf_disabled __read_mostly =
	IS_BUILTIN(CONFIG_BPF_UNPRIV_DEFAULT_OFF) ? 2 : 0;

static const struct bpf_map_ops * const bpf_map_types[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type)
#define BPF_MAP_TYPE(_id, _ops) \
	[_id] = &_ops,
#define BPF_LINK_TYPE(_id, _name)
#include "../../include/linux/bpf_types.h"
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
};










int orbpf_check_uarg_tail_zero(void __user *uaddr,
			     size_t expected_size,
			     size_t actual_size)
{
	unsigned char __user *addr = uaddr + expected_size;
	int res;

	if (unlikely(actual_size < expected_size)) {
		pr_err("using an obsolete libbpf?\n");
		return -EINVAL;
	}

	if (unlikely(actual_size > PAGE_SIZE)) {	 
		res = -E2BIG;
	}

	if (actual_size == expected_size)
		return 0;

	res = check_zeroed_user(addr, actual_size - expected_size);
	if (res < 0)
		goto failed;
	if (res == 0)
		res = -E2BIG;
	return 0;

failed:
	pr_err("using an obsolete orbpf.ko?\n");
	return res;
}

const struct bpf_map_ops bpf_map_offload_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = bpf_map_offload_map_alloc,
	.map_free = bpf_map_offload_map_free,
	.map_check_btf = map_check_no_btf,
};

static struct bpf_map *find_and_alloc_map(union bpf_attr *attr)
{
	const struct bpf_map_ops *ops;
	u32 type = attr->map_type;
	struct bpf_map *map;
	int err;

	if (type >= ARRAY_SIZE(bpf_map_types)) {
		return ERR_PTR(-EINVAL);
	}
	type = array_index_nospec(type, ARRAY_SIZE(bpf_map_types));
	ops = bpf_map_types[type];
	if (!ops) {
		return ERR_PTR(-EINVAL);
	}

	if (ops->map_alloc_check) {
		err = ops->map_alloc_check(attr);
		if (err) {
			return ERR_PTR(err);
		}
	}
	if (attr->map_ifindex)
		ops = &bpf_map_offload_ops;
	map = ops->map_alloc(attr);
	if (IS_ERR(map)) {
		return map;
	}
	map->ops = ops;
	map->map_type = type;
	return map;
}

static u32 bpf_map_value_size(const struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return round_up(map->value_size, 8) * num_possible_cpus();
	else if (IS_FD_MAP(map))
		return sizeof(u32);
	else
		return  map->value_size;
}

static void maybe_wait_bpf_programs(struct bpf_map *map)
{
	



	if (map->map_type == BPF_MAP_TYPE_HASH_OF_MAPS ||
	    map->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
		synchronize_rcu();
}

static int bpf_map_update_value(struct bpf_map *map, struct fd f, void *key,
				void *value, __u64 flags)
{
	int err;

	 
	if (bpf_map_is_dev_bound(map)) {


#if 1
		return -ENOTSUPP;
#endif
	} else if (map->map_type == BPF_MAP_TYPE_CPUMAP ||
		   map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {


#if 1
		return -ENOTSUPP;
#endif
	} else if (map->map_type == BPF_MAP_TYPE_SOCKHASH ||
		   map->map_type == BPF_MAP_TYPE_SOCKMAP) {


#if 1
		return -ENOTSUPP;
#endif
	} else if (IS_FD_PROG_ARRAY(map)) {
		return bpf_fd_array_map_update_elem(map, f.file, key, value,
						    flags);
	}

	bpf_disable_instrumentation();
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
		err = bpf_percpu_hash_update(map, key, value, flags, false);
	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		err = bpf_percpu_array_update(map, key, value, flags);
	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE) {
		err = bpf_percpu_cgroup_storage_update(map, key, value,
						       flags);
	} else if (IS_FD_ARRAY(map)) {
		rcu_read_lock();
		err = bpf_fd_array_map_update_elem(map, f.file, key, value,
						   flags);
		rcu_read_unlock();
	} else if (map->map_type == BPF_MAP_TYPE_HASH_OF_MAPS) {
		rcu_read_lock();
		err = bpf_fd_htab_map_update_elem(map, f.file, key, value,
						  flags);
		rcu_read_unlock();
	} else if (map->map_type == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY) {
		 
		err = bpf_fd_reuseport_array_update_elem(map, key, value,
							 flags);
	} else if (map->map_type == BPF_MAP_TYPE_QUEUE ||
		   map->map_type == BPF_MAP_TYPE_STACK) {
		err = map->ops->map_push_elem(map, value, flags);
	} else {
		rcu_read_lock();
		err = map->ops->map_update_elem(map, key, value, flags);
		rcu_read_unlock();
	}
	bpf_enable_instrumentation();
	maybe_wait_bpf_programs(map);

	return err;
}

static int bpf_map_copy_value(struct bpf_map *map, void *key, void *value,
			      __u64 flags)
{
	void *ptr;
	int err;

	if (bpf_map_is_dev_bound(map))


#if 1
		err = -ENOTSUPP;
#endif

	bpf_disable_instrumentation();
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
		err = bpf_percpu_hash_copy(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		err = bpf_percpu_array_copy(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE) {
		err = bpf_percpu_cgroup_storage_copy(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_STACK_TRACE) {
		err = bpf_stackmap_copy(map, key, value);
	} else if (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map)) {
		err = bpf_fd_array_map_lookup_elem(map, key, value);
	} else if (IS_FD_HASH(map)) {
		err = bpf_fd_htab_map_lookup_elem(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY) {
		err = bpf_fd_reuseport_array_lookup_elem(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_QUEUE ||
		   map->map_type == BPF_MAP_TYPE_STACK) {
		err = map->ops->map_peek_elem(map, value);
	} else if (map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
		 
		err = bpf_struct_ops_map_sys_lookup_elem(map, key, value);
	} else {
		rcu_read_lock();
		if (map->ops->map_lookup_elem_sys_only)
			ptr = map->ops->map_lookup_elem_sys_only(map, key);
		else
			ptr = map->ops->map_lookup_elem(map, key);
		if (IS_ERR(ptr)) {
			err = PTR_ERR(ptr);
		} else if (!ptr) {
			err = -ENOENT;
		} else {
			err = 0;
			if (flags & BPF_F_LOCK)
				 
				orbpf_copy_map_value_locked(map, value, ptr, true);
			else
				orbpf_copy_map_value(map, value, ptr);
			 
			orbpf_check_and_init_map_lock(map, value);
		}
		rcu_read_unlock();
	}

	bpf_enable_instrumentation();
	maybe_wait_bpf_programs(map);

	return err;
}





static void *__bpf_map_area_alloc(u64 size, int numa_node, bool mmapable)
{
	









	const gfp_t gfp = __GFP_NOWARN | __GFP_ZERO | __GFP_ACCOUNT;
	unsigned int flags = 0;
	unsigned long align = 1;
	void *area;

	if (size >= SIZE_MAX)
		return NULL;

	 
	if (mmapable) {
		BUG_ON(!PAGE_ALIGNED(size));
		align = SHMLBA;
		flags = VM_USERMAP;
	} else if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		area = kmalloc_node(size, gfp | GFP_USER | __GFP_NORETRY,
				    numa_node);
		if (area != NULL)
			return area;
	}

	return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
			gfp | GFP_KERNEL | __GFP_RETRY_MAYFAIL, PAGE_KERNEL,
			flags, numa_node, __builtin_return_address(0));
}

void *bpf_map_area_alloc(u64 size, int numa_node)
{
	return __bpf_map_area_alloc(size, numa_node, false);
}

void *bpf_map_area_mmapable_alloc(u64 size, int numa_node)
{
	return __bpf_map_area_alloc(size, numa_node, true);
}

void bpf_map_area_free(void *area)
{
	kvfree(area);
}

static u32 bpf_map_flags_retain_permanent(u32 flags)
{
	






	return flags & ~(BPF_F_RDONLY | BPF_F_WRONLY);
}

void bpf_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr)
{
	map->map_type = attr->map_type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = bpf_map_flags_retain_permanent(attr->map_flags);
	map->numa_node = bpf_map_attr_numa_node(attr);
}

static int bpf_map_alloc_id(struct bpf_map *map)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&map_idr_lock);
	id = idr_alloc_cyclic(&map_idr, map, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		map->id = id;
	spin_unlock_bh(&map_idr_lock);
	idr_preload_end();

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

void bpf_map_free_id(struct bpf_map *map, bool do_idr_lock)
{
	unsigned long flags;

	




	if (!map->id)
		return;

	if (do_idr_lock)
		spin_lock_irqsave(&map_idr_lock, flags);
	else
		__acquire(&map_idr_lock);

	idr_remove(&map_idr, map->id);
	map->id = 0;

	if (do_idr_lock)
		spin_unlock_irqrestore(&map_idr_lock, flags);
	else
		__release(&map_idr_lock);
}

#ifdef CONFIG_MEMCG_KMEM
static void bpf_map_save_memcg(struct bpf_map *map)
{
	map->memcg = get_mem_cgroup_from_mm(current->mm);
}

static void bpf_map_release_memcg(struct bpf_map *map)
{
	mem_cgroup_put(map->memcg);
}

void *bpf_map_kmalloc_node(const struct bpf_map *map, size_t size, gfp_t flags,
			   int node)
{
	struct mem_cgroup *old_memcg;
	void *ptr;

	old_memcg = set_active_memcg(map->memcg);
	ptr = kmalloc_node(size, flags | __GFP_ACCOUNT, node);
	set_active_memcg(old_memcg);

	return ptr;
}

void *bpf_map_kzalloc(const struct bpf_map *map, size_t size, gfp_t flags)
{
	struct mem_cgroup *old_memcg;
	void *ptr;

	old_memcg = set_active_memcg(map->memcg);
	ptr = kzalloc(size, flags | __GFP_ACCOUNT);
	set_active_memcg(old_memcg);

	return ptr;
}

void __percpu *bpf_map_alloc_percpu(const struct bpf_map *map, size_t size,
				    size_t align, gfp_t flags)
{
	struct mem_cgroup *old_memcg;
	void __percpu *ptr;

	old_memcg = set_active_memcg(map->memcg);
	ptr = __alloc_percpu_gfp(size, align, flags | __GFP_ACCOUNT);
	set_active_memcg(old_memcg);

	return ptr;
}

#else
static void bpf_map_save_memcg(struct bpf_map *map)
{
}

static void bpf_map_release_memcg(struct bpf_map *map)
{
}
#endif

 
static void bpf_map_free_deferred(struct work_struct *work)
{
	struct bpf_map *map = container_of(work, struct bpf_map, work);

	security_bpf_map_free(map);
	bpf_map_release_memcg(map);
	 
	map->ops->map_free(map);
}

static void bpf_map_put_uref(struct bpf_map *map)
{
	if (atomic64_dec_and_test(&map->usercnt)) {
		if (map->ops->map_release_uref)
			map->ops->map_release_uref(map);
	}
}




static void __bpf_map_put(struct bpf_map *map, bool do_idr_lock)
{
	if (atomic64_dec_and_test(&map->refcnt)) {
		 
		bpf_map_free_id(map, do_idr_lock);
		orbpf_btf_put(map->btf);
		INIT_WORK(&map->work, bpf_map_free_deferred);
		schedule_work(&map->work);
	}
}

void bpf_map_put(struct bpf_map *map)
{
	__bpf_map_put(map, true);
}
EXPORT_SYMBOL_GPL(bpf_map_put);

void bpf_map_put_with_uref(struct bpf_map *map)
{
	bpf_map_put_uref(map);
	bpf_map_put(map);
}

static int bpf_map_release(struct inode *inode, struct file *filp)
{
	struct bpf_map *map = filp->private_data;

	if (map->ops->map_release)
		map->ops->map_release(map, filp);

	bpf_map_put_with_uref(map);
	return 0;
}

static fmode_t map_get_sys_perms(struct bpf_map *map, struct fd f)
{
	fmode_t mode = f.file->f_mode;

	


	if (READ_ONCE(map->frozen))
		mode &= ~FMODE_CAN_WRITE;
	return mode;
}

#ifdef CONFIG_PROC_FS




static unsigned long bpf_map_memory_footprint(const struct bpf_map *map)
{
	unsigned long size;

	size = round_up(map->key_size + bpf_map_value_size(map), 8);

	return round_up(map->max_entries * size, PAGE_SIZE);
}

static void bpf_map_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct bpf_map *map = filp->private_data;
	const struct bpf_array *array;
	u32 type = 0, jited = 0;

	if (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
		array = container_of(map, struct bpf_array, map);
		type  = array->aux->type;
		jited = array->aux->jited;
	}

	seq_printf(m,
		   "map_type:\t%u\n"
		   "key_size:\t%u\n"
		   "value_size:\t%u\n"
		   "max_entries:\t%u\n"
		   "map_flags:\t%#x\n"
		   "memlock:\t%lu\n"
		   "map_id:\t%u\n"
		   "frozen:\t%u\n",
		   map->map_type,
		   map->key_size,
		   map->value_size,
		   map->max_entries,
		   map->map_flags,
		   bpf_map_memory_footprint(map),
		   map->id,
		   READ_ONCE(map->frozen));
	if (type) {
		seq_printf(m, "owner_prog_type:\t%u\n", type);
		seq_printf(m, "owner_jited:\t%u\n", jited);
	}
}
#endif

static ssize_t bpf_dummy_read(struct file *filp, char __user *buf, size_t siz,
			      loff_t *ppos)
{
	


	return -EINVAL;
}

static ssize_t bpf_dummy_write(struct file *filp, const char __user *buf,
			       size_t siz, loff_t *ppos)
{
	


	return -EINVAL;
}

 
static void bpf_map_mmap_open(struct vm_area_struct *vma)
{
	struct bpf_map *map = vma->vm_file->private_data;

	if (vma->vm_flags & VM_MAYWRITE) {
		mutex_lock(&map->freeze_mutex);
		map->writecnt++;
		mutex_unlock(&map->freeze_mutex);
	}
}

 
static void bpf_map_mmap_close(struct vm_area_struct *vma)
{
	struct bpf_map *map = vma->vm_file->private_data;

	if (vma->vm_flags & VM_MAYWRITE) {
		mutex_lock(&map->freeze_mutex);
		map->writecnt--;
		mutex_unlock(&map->freeze_mutex);
	}
}

static const struct vm_operations_struct bpf_map_default_vmops = {
	.open		= bpf_map_mmap_open,
	.close		= bpf_map_mmap_close,
};

static int bpf_map_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct bpf_map *map = filp->private_data;
	int err;

	if (!map->ops->map_mmap || map_value_has_spin_lock(map))
		return -ENOTSUPP;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	mutex_lock(&map->freeze_mutex);

	if (vma->vm_flags & VM_WRITE) {
		if (map->frozen) {
			err = -EPERM;
			goto out;
		}
		




		if (map->map_flags & BPF_F_RDONLY_PROG) {
			err = -EACCES;
			goto out;
		}
	}

	 
	vma->vm_ops = &bpf_map_default_vmops;
	vma->vm_private_data = map;
	vm_flags_clear(vma, VM_MAYEXEC);
	if (!(vma->vm_flags & VM_WRITE))
		 
		vm_flags_clear(vma, VM_MAYWRITE);

	err = map->ops->map_mmap(map, vma);
	if (err)
		goto out;

	if (vma->vm_flags & VM_MAYWRITE)
		map->writecnt++;
out:
	mutex_unlock(&map->freeze_mutex);
	return err;
}

static __poll_t bpf_map_poll(struct file *filp, struct poll_table_struct *pts)
{
	struct bpf_map *map = filp->private_data;

	if (map->ops->map_poll)
		return map->ops->map_poll(map, filp, pts);

	return EPOLLERR;
}

const struct file_operations bpf_map_fops = {
	.owner		= THIS_MODULE,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_map_show_fdinfo,
#endif
	.release	= bpf_map_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
	.mmap		= bpf_map_mmap,
	.poll		= bpf_map_poll,
};

int bpf_map_new_fd(struct bpf_map *map, int flags)
{
	int ret;

	ret = security_bpf_map(map, OPEN_FMODE(flags));
	if (ret < 0)
		return ret;

	return anon_inode_getfd("bpf-map", &bpf_map_fops, map,
				flags | O_CLOEXEC);
}

int bpf_get_file_flag(int flags)
{
	if ((flags & BPF_F_RDONLY) && (flags & BPF_F_WRONLY))
		return -EINVAL;
	if (flags & BPF_F_RDONLY)
		return O_RDONLY;
	if (flags & BPF_F_WRONLY)
		return O_WRONLY;
	return O_RDWR;
}

 
#define CHECK_ATTR(CMD) \
	memchr_inv((void *) &attr->CMD##_LAST_FIELD + \
		   sizeof(attr->CMD##_LAST_FIELD), 0, \
		   sizeof(*attr) - \
		   offsetof(union bpf_attr, CMD##_LAST_FIELD) - \
		   sizeof(attr->CMD##_LAST_FIELD)) != NULL




int bpf_obj_name_cpy(char *dst, const char *src, unsigned int size)
{
	const char *end = src + size;
	const char *orig_src = src;

	memset(dst, 0, size);
	 
	while (src < end && *src) {
		if (!isalnum(*src) &&
		    *src != '_' && *src != '.')
			return -EINVAL;
		*dst++ = *src++;
	}

	 
	if (src == end)
		return -EINVAL;

	return src - orig_src;
}

int map_check_no_btf(const struct bpf_map *map,
		     const struct btf *btf,
		     const struct btf_type *key_type,
		     const struct btf_type *value_type)
{
	return -ENOTSUPP;
}

static int map_check_btf(struct bpf_map *map, const struct btf *btf,
			 u32 btf_key_id, u32 btf_value_id)
{
	const struct btf_type *key_type, *value_type;
	u32 key_size, value_size;
	int ret = 0;

	 
	if (btf_key_id) {
		key_type = btf_type_id_size(btf, &btf_key_id, &key_size);
		if (!key_type || key_size != map->key_size)
			return -EINVAL;
	} else {
		key_type = btf_type_by_id(btf, 0);
		if (!map->ops->map_check_btf)
			return -EINVAL;
	}

	value_type = btf_type_id_size(btf, &btf_value_id, &value_size);
	if (!value_type || value_size != map->value_size)
		return -EINVAL;

	map->spin_lock_off = btf_find_spin_lock(btf, value_type);

	if (map_value_has_spin_lock(map)) {
		if (map->map_flags & BPF_F_RDONLY_PROG)
			return -EACCES;
		if (map->map_type != BPF_MAP_TYPE_HASH &&
		    map->map_type != BPF_MAP_TYPE_ARRAY &&
		    map->map_type != BPF_MAP_TYPE_CGROUP_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_SK_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_INODE_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_TASK_STORAGE)
			return -ENOTSUPP;
		if (map->spin_lock_off + sizeof(struct bpf_spin_lock) >
		    map->value_size) {
			WARN_ONCE(1,
				  "verifier bug spin_lock_off %d value_size %d\n",
				  map->spin_lock_off, map->value_size);
			return -EFAULT;
		}
	}

	if (map->ops->map_check_btf)
		ret = map->ops->map_check_btf(map, btf, key_type, value_type);

	return ret;
}

#define BPF_MAP_CREATE_LAST_FIELD btf_vmlinux_value_type_id
 
static int map_create(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_map *map;
	int f_flags;
	int err;

	err = CHECK_ATTR(BPF_MAP_CREATE);
	if (err)
		return -EINVAL;

	if (attr->btf_vmlinux_value_type_id) {
		if (attr->map_type != BPF_MAP_TYPE_STRUCT_OPS ||
		    attr->btf_key_type_id || attr->btf_value_type_id)
			return -EINVAL;
	} else if (attr->btf_key_type_id && !attr->btf_value_type_id) {
		return -EINVAL;
	}

	f_flags = bpf_get_file_flag(attr->map_flags);
	if (f_flags < 0)
		return f_flags;

	if (numa_node != NUMA_NO_NODE &&
	    ((unsigned int)numa_node >= nr_node_ids ||
	     !node_online(numa_node)))
		return -EINVAL;

	 
	map = find_and_alloc_map(attr);
	if (IS_ERR(map))
		return PTR_ERR(map);

	err = bpf_obj_name_cpy(map->name, attr->map_name,
			       sizeof(attr->map_name));
	if (err < 0)
		goto free_map;

	atomic64_set(&map->refcnt, 1);
	atomic64_set(&map->usercnt, 1);
	mutex_init(&map->freeze_mutex);

	map->spin_lock_off = -EINVAL;
	if (attr->btf_key_type_id || attr->btf_value_type_id ||
	    





	    attr->btf_vmlinux_value_type_id) {
		struct btf *btf;

		btf = btf_get_by_fd(attr->btf_fd);
		if (IS_ERR(btf)) {
			err = PTR_ERR(btf);
			goto free_map;
		}
		if (btf_is_kernel(btf)) {
			orbpf_btf_put(btf);
			err = -EACCES;
			goto free_map;
		}
		map->btf = btf;

		if (attr->btf_value_type_id) {
			err = map_check_btf(map, btf, attr->btf_key_type_id,
					    attr->btf_value_type_id);
			if (err)
				goto free_map;
		}

		map->btf_key_type_id = attr->btf_key_type_id;
		map->btf_value_type_id = attr->btf_value_type_id;
		map->btf_vmlinux_value_type_id =
			attr->btf_vmlinux_value_type_id;
	}

	err = security_bpf_map_alloc(map);
	if (err)
		goto free_map;

	err = bpf_map_alloc_id(map);
	if (err)
		goto free_map_sec;

	bpf_map_save_memcg(map);

	err = bpf_map_new_fd(map, f_flags);
	if (err < 0) {
		





		bpf_map_put_with_uref(map);
		return err;
	}

	return err;

free_map_sec:
	security_bpf_map_free(map);
free_map:
	orbpf_btf_put(map->btf);
	map->ops->map_free(map);
	return err;
}




struct bpf_map *__bpf_map_get(struct fd f)
{
	if (!f.file)
		return ERR_PTR(-EBADF);
	if (f.file->f_op != &bpf_map_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	return f.file->private_data;
}

void bpf_map_inc(struct bpf_map *map)
{
	atomic64_inc(&map->refcnt);
}
EXPORT_SYMBOL_GPL(bpf_map_inc);

void bpf_map_inc_with_uref(struct bpf_map *map)
{
	atomic64_inc(&map->refcnt);
	atomic64_inc(&map->usercnt);
}
EXPORT_SYMBOL_GPL(bpf_map_inc_with_uref);

struct bpf_map *bpf_map_get(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_map *map;

	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return map;

	bpf_map_inc(map);
	fdput(f);

	return map;
}

struct bpf_map *bpf_map_get_with_uref(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_map *map;

	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return map;

	bpf_map_inc_with_uref(map);
	fdput(f);

	return map;
}

 
static struct bpf_map *__bpf_map_inc_not_zero(struct bpf_map *map, bool uref)
{
	int refold;

	refold = atomic64_fetch_add_unless(&map->refcnt, 1, 0);
	if (!refold)
		return ERR_PTR(-ENOENT);
	if (uref)
		atomic64_inc(&map->usercnt);

	return map;
}













int __weak bpf_stackmap_copy(struct bpf_map *map, void *key, void *value)
{
	return -ENOTSUPP;
}

static void *__bpf_copy_key(void __user *ukey, u64 key_size)
{
	if (key_size)
		return memdup_user(ukey, key_size);

	if (ukey)
		return ERR_PTR(-EINVAL);

	return NULL;
}

 
#define BPF_MAP_LOOKUP_ELEM_LAST_FIELD flags

static int map_lookup_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_LOOKUP_ELEM))
		return -EINVAL;

	if (attr->flags & ~BPF_F_LOCK)
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	if ((attr->flags & BPF_F_LOCK) &&
	    !map_value_has_spin_lock(map)) {
		err = -EINVAL;
		goto err_put;
	}

	key = __bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	value_size = bpf_map_value_size(map);

	err = -ENOMEM;
	value = kvmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	err = bpf_map_copy_value(map, key, value, attr->flags);
	if (err)
		goto free_value;

	err = -EFAULT;
	if (copy_to_user(uvalue, value, value_size) != 0)
		goto free_value;

	err = 0;

free_value:
	kvfree(value);
free_key:
	kvfree(key);
err_put:
	fdput(f);
	return err;
}


#define BPF_MAP_UPDATE_ELEM_LAST_FIELD flags

static int map_update_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	if ((attr->flags & BPF_F_LOCK) &&
	    !map_value_has_spin_lock(map)) {
		err = -EINVAL;
		goto err_put;
	}

	key = __bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		value_size = round_up(map->value_size, 8) * num_possible_cpus();
	else
		value_size = map->value_size;

	err = -ENOMEM;
	value = kvmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	err = -EFAULT;
	if (copy_from_user(value, uvalue, value_size) != 0)
		goto free_value;

	err = bpf_map_update_value(map, f, key, value, attr->flags);

free_value:
	kvfree(value);
free_key:
	kvfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_DELETE_ELEM_LAST_FIELD key

static int map_delete_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	struct fd f;
	void *key;
	int err;

	if (CHECK_ATTR(BPF_MAP_DELETE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	key = __bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	if (bpf_map_is_dev_bound(map)) {


#if 1
		err = -ENOTSUPP;
#endif
		goto out;
	} else if (IS_FD_PROG_ARRAY(map) ||
		   map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
		 
		err = map->ops->map_delete_elem(map, key);
		goto out;
	}

	bpf_disable_instrumentation();
	rcu_read_lock();
	err = map->ops->map_delete_elem(map, key);
	rcu_read_unlock();
	bpf_enable_instrumentation();
	maybe_wait_bpf_programs(map);
out:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

 
#define BPF_MAP_GET_NEXT_KEY_LAST_FIELD next_key

static int map_get_next_key(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *unext_key = u64_to_user_ptr(attr->next_key);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *next_key;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_GET_NEXT_KEY))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	if (ukey) {
		key = __bpf_copy_key(ukey, map->key_size);
		if (IS_ERR(key)) {
			err = PTR_ERR(key);
			goto err_put;
		}
	} else {
		key = NULL;
	}

	err = -ENOMEM;
	next_key = kmalloc(map->key_size, GFP_USER);
	if (!next_key)
		goto free_key;

	if (bpf_map_is_dev_bound(map)) {


#if 1
		err = -ENOTSUPP;
#endif
		goto out;
	}

	rcu_read_lock();
	err = map->ops->map_get_next_key(map, key, next_key);
	rcu_read_unlock();
out:
	if (err)
		goto free_next_key;

	err = -EFAULT;
	if (copy_to_user(unext_key, next_key, map->key_size) != 0)
		goto free_next_key;

	err = 0;

free_next_key:
	kfree(next_key);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

int generic_map_delete_batch(struct bpf_map *map,
			     const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	void __user *keys = u64_to_user_ptr(attr->batch.keys);
	u32 cp, max_count;
	int err = 0;
	void *key;

	if (attr->batch.elem_flags & ~BPF_F_LOCK)
		return -EINVAL;

	if ((attr->batch.elem_flags & BPF_F_LOCK) &&
	    !map_value_has_spin_lock(map)) {
		return -EINVAL;
	}

	max_count = attr->batch.count;
	if (!max_count)
		return 0;

	key = kmalloc(map->key_size, GFP_USER | __GFP_NOWARN);
	if (!key)
		return -ENOMEM;

	for (cp = 0; cp < max_count; cp++) {
		err = -EFAULT;
		if (copy_from_user(key, keys + cp * map->key_size,
				   map->key_size))
			break;

		if (bpf_map_is_dev_bound(map)) {


#if 1
			err = -ENOTSUPP;
#endif
			break;
		}

		bpf_disable_instrumentation();
		rcu_read_lock();
		err = map->ops->map_delete_elem(map, key);
		rcu_read_unlock();
		bpf_enable_instrumentation();
		maybe_wait_bpf_programs(map);
		if (err)
			break;
	}
	if (copy_to_user(&uattr->batch.count, &cp, sizeof(cp)))
		err = -EFAULT;

	kfree(key);
	return err;
}

int generic_map_update_batch(struct bpf_map *map,
			     const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	void __user *values = u64_to_user_ptr(attr->batch.values);
	void __user *keys = u64_to_user_ptr(attr->batch.keys);
	u32 value_size, cp, max_count;
	int ufd = attr->map_fd;
	void *key, *value;
	struct fd f;
	int err = 0;

	f = fdget(ufd);
	if (attr->batch.elem_flags & ~BPF_F_LOCK)
		return -EINVAL;

	if ((attr->batch.elem_flags & BPF_F_LOCK) &&
	    !map_value_has_spin_lock(map)) {
		return -EINVAL;
	}

	value_size = bpf_map_value_size(map);

	max_count = attr->batch.count;
	if (!max_count)
		return 0;

	key = kmalloc(map->key_size, GFP_USER | __GFP_NOWARN);
	if (!key)
		return -ENOMEM;

	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value) {
		kfree(key);
		return -ENOMEM;
	}

	for (cp = 0; cp < max_count; cp++) {
		err = -EFAULT;
		if (copy_from_user(key, keys + cp * map->key_size,
		    map->key_size) ||
		    copy_from_user(value, values + cp * value_size, value_size))
			break;

		err = bpf_map_update_value(map, f, key, value,
					   attr->batch.elem_flags);

		if (err)
			break;
	}

	if (copy_to_user(&uattr->batch.count, &cp, sizeof(cp)))
		err = -EFAULT;

	kfree(value);
	kfree(key);
	return err;
}

#define MAP_LOOKUP_RETRIES 3

int generic_map_lookup_batch(struct bpf_map *map,
				    const union bpf_attr *attr,
				    union bpf_attr __user *uattr)
{
	void __user *uobatch = u64_to_user_ptr(attr->batch.out_batch);
	void __user *ubatch = u64_to_user_ptr(attr->batch.in_batch);
	void __user *values = u64_to_user_ptr(attr->batch.values);
	void __user *keys = u64_to_user_ptr(attr->batch.keys);
	void *buf, *buf_prevkey, *prev_key, *key, *value;
	int err, retry = MAP_LOOKUP_RETRIES;
	u32 value_size, cp, max_count;

	if (attr->batch.elem_flags & ~BPF_F_LOCK)
		return -EINVAL;

	if ((attr->batch.elem_flags & BPF_F_LOCK) &&
	    !map_value_has_spin_lock(map))
		return -EINVAL;

	value_size = bpf_map_value_size(map);

	max_count = attr->batch.count;
	if (!max_count)
		return 0;

	if (put_user(0, &uattr->batch.count))
		return -EFAULT;

	buf_prevkey = kmalloc(map->key_size, GFP_USER | __GFP_NOWARN);
	if (!buf_prevkey)
		return -ENOMEM;

	buf = kmalloc(map->key_size + value_size, GFP_USER | __GFP_NOWARN);
	if (!buf) {
		kfree(buf_prevkey);
		return -ENOMEM;
	}

	err = -EFAULT;
	prev_key = NULL;
	if (ubatch && copy_from_user(buf_prevkey, ubatch, map->key_size))
		goto free_buf;
	key = buf;
	value = key + map->key_size;
	if (ubatch)
		prev_key = buf_prevkey;

	for (cp = 0; cp < max_count;) {
		rcu_read_lock();
		err = map->ops->map_get_next_key(map, prev_key, key);
		rcu_read_unlock();
		if (err)
			break;
		err = bpf_map_copy_value(map, key, value,
					 attr->batch.elem_flags);

		if (err == -ENOENT) {
			if (retry) {
				retry--;
				continue;
			}
			err = -EINTR;
			break;
		}

		if (err)
			goto free_buf;

		if (copy_to_user(keys + cp * map->key_size, key,
				 map->key_size)) {
			err = -EFAULT;
			goto free_buf;
		}
		if (copy_to_user(values + cp * value_size, value, value_size)) {
			err = -EFAULT;
			goto free_buf;
		}

		if (!prev_key)
			prev_key = buf_prevkey;

		swap(prev_key, key);
		retry = MAP_LOOKUP_RETRIES;
		cp++;
	}

	if (err == -EFAULT)
		goto free_buf;

	if ((copy_to_user(&uattr->batch.count, &cp, sizeof(cp)) ||
		    (cp && copy_to_user(uobatch, prev_key, map->key_size))))
		err = -EFAULT;

free_buf:
	kfree(buf_prevkey);
	kfree(buf);
	return err;
}

#define BPF_MAP_LOOKUP_AND_DELETE_ELEM_LAST_FIELD value

static int map_lookup_and_delete_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_LOOKUP_AND_DELETE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_READ) ||
	    !(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	key = __bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	value_size = map->value_size;

	err = -ENOMEM;
	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	if (map->map_type == BPF_MAP_TYPE_QUEUE ||
	    map->map_type == BPF_MAP_TYPE_STACK) {
		err = map->ops->map_pop_elem(map, value);
	} else {
		err = -ENOTSUPP;
	}

	if (err)
		goto free_value;

	if (copy_to_user(uvalue, value, value_size) != 0) {
		err = -EFAULT;
		goto free_value;
	}

	err = 0;

free_value:
	kfree(value);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_FREEZE_LAST_FIELD map_fd

static int map_freeze(const union bpf_attr *attr)
{
	int err = 0, ufd = attr->map_fd;
	struct bpf_map *map;
	struct fd f;

	if (CHECK_ATTR(BPF_MAP_FREEZE))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if (map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
		fdput(f);
		return -ENOTSUPP;
	}

	mutex_lock(&map->freeze_mutex);

	if (map->writecnt) {
		err = -EBUSY;
		goto err_put;
	}
	if (READ_ONCE(map->frozen)) {
		err = -EBUSY;
		goto err_put;
	}
	if (!bpf_capable()) {
		err = -EPERM;
		goto err_put;
	}

	WRITE_ONCE(map->frozen, true);
err_put:
	mutex_unlock(&map->freeze_mutex);
	fdput(f);
	return err;
}

static const struct bpf_prog_ops * const bpf_prog_types[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	[_id] = & _name ## _prog_ops,
#define BPF_MAP_TYPE(_id, _ops)
#define BPF_LINK_TYPE(_id, _name)
#include "../../include/linux/bpf_types.h"
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
};

static int find_prog_type(enum bpf_prog_type type, struct bpf_prog *prog)
{
	const struct bpf_prog_ops *ops;

	if (type >= ARRAY_SIZE(bpf_prog_types))
		return -EINVAL;
	type = array_index_nospec(type, ARRAY_SIZE(bpf_prog_types));
	ops = bpf_prog_types[type];
	if (!ops)
		return -EINVAL;

	if (!bpf_prog_is_dev_bound(prog->aux))
		prog->aux->ops = ops;
	else


#if 1
		return -ENOTSUPP;
#endif
	prog->type = type;
	return 0;
}































#if 1
#define bpf_audit_prog(prog, op) do { } while (0)
#endif

static int bpf_prog_alloc_id(struct bpf_prog *prog)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&prog_idr_lock);
	id = idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		prog->aux->id = id;
	spin_unlock_bh(&prog_idr_lock);
	idr_preload_end();

	 
	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

void bpf_prog_free_id(struct bpf_prog *prog, bool do_idr_lock)
{
	




	if (!prog->aux->id)
		return;

	if (do_idr_lock)
		spin_lock_bh(&prog_idr_lock);
	else
		__acquire(&prog_idr_lock);

	idr_remove(&prog_idr, prog->aux->id);
	prog->aux->id = 0;

	if (do_idr_lock)
		spin_unlock_bh(&prog_idr_lock);
	else
		__release(&prog_idr_lock);
}

static void __bpf_prog_put_rcu(struct rcu_head *rcu)
{
	struct bpf_prog_aux *aux = container_of(rcu, struct bpf_prog_aux, rcu);

	kvfree(aux->func_info);
	kfree(aux->func_info_aux);
	free_uid(aux->user);
	security_bpf_prog_free(aux);
	bpf_prog_free(aux->prog);
}

static void __bpf_prog_put_noref(struct bpf_prog *prog, bool deferred)
{
	bpf_prog_kallsyms_del_all(prog);
	orbpf_btf_put(prog->aux->btf);
	kvfree(prog->aux->jited_linfo);
	kvfree(prog->aux->linfo);






	if (deferred) {
		if (prog->aux->sleepable)
			call_rcu_tasks_trace(&prog->aux->rcu, __bpf_prog_put_rcu);
		else
			call_rcu(&prog->aux->rcu, __bpf_prog_put_rcu);
	} else {
		__bpf_prog_put_rcu(&prog->aux->rcu);
	}
}

static void __bpf_prog_put(struct bpf_prog *prog, bool do_idr_lock)
{
	if (atomic64_dec_and_test(&prog->aux->refcnt)) {
		
		bpf_audit_prog(prog, BPF_AUDIT_UNLOAD);
		 
		bpf_prog_free_id(prog, do_idr_lock);
		__bpf_prog_put_noref(prog, true);
	}
}

void bpf_prog_put(struct bpf_prog *prog)
{
	__bpf_prog_put(prog, true);
}
EXPORT_SYMBOL_GPL(bpf_prog_put);

static int bpf_prog_release(struct inode *inode, struct file *filp)
{
	struct bpf_prog *prog = filp->private_data;

	bpf_prog_put(prog);
	return 0;
}

static void bpf_prog_get_stats(const struct bpf_prog *prog,
			       struct bpf_prog_stats *stats)
{
	u64 nsecs = 0, cnt = 0, misses = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		const struct bpf_prog_stats *st;
		unsigned int start;
		u64 tnsecs, tcnt, tmisses;

		st = per_cpu_ptr(prog->stats, cpu);
		do {
			start = u64_stats_fetch_begin_irq(&st->syncp);
			tnsecs = st->nsecs;
			tcnt = st->cnt;
			tmisses = st->misses;
		} while (u64_stats_fetch_retry_irq(&st->syncp, start));
		nsecs += tnsecs;
		cnt += tcnt;
		misses += tmisses;
	}
	stats->nsecs = nsecs;
	stats->cnt = cnt;
	stats->misses = misses;
}

#ifdef CONFIG_PROC_FS
static void bpf_prog_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct bpf_prog *prog = filp->private_data;
	char prog_tag[sizeof(prog->tag) * 2 + 1] = { };
	struct bpf_prog_stats stats;

	bpf_prog_get_stats(prog, &stats);
	bin2hex(prog_tag, prog->tag, sizeof(prog->tag));
	seq_printf(m,
		   "prog_type:\t%u\n"
		   "prog_jited:\t%u\n"
		   "prog_tag:\t%s\n"
		   "memlock:\t%llu\n"
		   "prog_id:\t%u\n"
		   "run_time_ns:\t%llu\n"
		   "run_cnt:\t%llu\n"
		   "recursion_misses:\t%llu\n",
		   prog->type,
		   prog->jited,
		   prog_tag,
		   prog->pages * 1ULL << PAGE_SHIFT,
		   prog->aux->id,
		   stats.nsecs,
		   stats.cnt,
		   stats.misses);
}
#endif

const struct file_operations bpf_prog_fops = {
	.owner		= THIS_MODULE,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_prog_show_fdinfo,
#endif
	.release	= bpf_prog_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
};

int bpf_prog_new_fd(struct bpf_prog *prog)
{
	int ret;

	ret = security_bpf_prog(prog);
	if (ret < 0)
		return ret;

	return anon_inode_getfd("bpf-prog", &bpf_prog_fops, prog,
				O_RDWR | O_CLOEXEC);
}

static struct bpf_prog *____bpf_prog_get(struct fd f)
{
	if (!f.file)
		return ERR_PTR(-EBADF);
	if (f.file->f_op != &bpf_prog_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	return f.file->private_data;
}




















void bpf_prog_inc(struct bpf_prog *prog)
{
	atomic64_inc(&prog->aux->refcnt);
}
EXPORT_SYMBOL_GPL(bpf_prog_inc);

 
struct bpf_prog *bpf_prog_inc_not_zero(struct bpf_prog *prog)
{
	int refold;

	refold = atomic64_fetch_add_unless(&prog->aux->refcnt, 1, 0);

	if (!refold)
		return ERR_PTR(-ENOENT);

	return prog;
}
EXPORT_SYMBOL_GPL(bpf_prog_inc_not_zero);

bool bpf_prog_get_ok(struct bpf_prog *prog,
			    enum bpf_prog_type *attach_type, bool attach_drv)
{
	 
	if (!attach_type)
		return true;

	if (prog->type != *attach_type)
		return false;
	if (bpf_prog_is_dev_bound(prog->aux) && !attach_drv)
		return false;

	return true;
}

static struct bpf_prog *__bpf_prog_get(u32 ufd, enum bpf_prog_type *attach_type,
				       bool attach_drv)
{
	struct fd f = fdget(ufd);
	struct bpf_prog *prog;

	prog = ____bpf_prog_get(f);
	if (IS_ERR(prog))
		return prog;
	if (!bpf_prog_get_ok(prog, attach_type, attach_drv)) {
		prog = ERR_PTR(-EINVAL);
		goto out;
	}

	bpf_prog_inc(prog);
out:
	fdput(f);
	return prog;
}

struct bpf_prog *bpf_prog_get(u32 ufd)
{
	return __bpf_prog_get(ufd, NULL, false);
}














































































































































































 
#define	BPF_PROG_LOAD_LAST_FIELD attach_prog_fd

static int bpf_prog_load(union bpf_attr *attr, union bpf_attr __user *uattr,
	char __user *prog_label, u32 prog_label_len)
{
	enum bpf_prog_type type = attr->prog_type;
	struct bpf_prog *prog;
	
	int err;
	char license[128];
	bool is_gpl;

	if (CHECK_ATTR(BPF_PROG_LOAD))
		return -EINVAL;

	if (attr->prog_flags & ~(BPF_F_STRICT_ALIGNMENT |
				 BPF_F_ANY_ALIGNMENT |
				 BPF_F_TEST_STATE_FREQ |
				 BPF_F_SLEEPABLE |
				 BPF_F_TEST_RND_HI32))
		return -EINVAL;

	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) &&
	    (attr->prog_flags & BPF_F_ANY_ALIGNMENT) &&
	    !bpf_capable())
		return -EPERM;

	 
	if (strncpy_from_user(license, u64_to_user_ptr(attr->license),
			      sizeof(license) - 1) < 0)
		return -EFAULT;
	license[sizeof(license) - 1] = 0;

	 
	is_gpl = license_is_gpl_compatible(license);

	if (attr->insn_cnt == 0 ||
	    attr->insn_cnt > (bpf_capable() ? BPF_COMPLEXITY_LIMIT_INSNS : BPF_MAXINSNS))
		return -E2BIG;
	if (type != BPF_PROG_TYPE_SOCKET_FILTER &&
	    type != BPF_PROG_TYPE_CGROUP_SKB &&
	    !bpf_capable())
		return -EPERM;















































	 
	prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
	if (!prog) {






		return -ENOMEM;
	}

	 
	if (prog_label_len > 0) {
		if (unlikely(strncpy_from_user(prog->prog_label, prog_label,
				      prog_label_len) < 0))
		{
			return -EFAULT;
		}
		prog->prog_label[prog_label_len] = '\0';
		prog->prog_label_len = prog_label_len;
	}

	prog->expected_attach_type = attr->expected_attach_type;





	prog->aux->offload_requested = !!attr->prog_ifindex;
	prog->aux->sleepable = attr->prog_flags & BPF_F_SLEEPABLE;

	err = security_bpf_prog_alloc(prog->aux);
	if (err)
		goto free_prog;

	prog->aux->user = get_current_user();
	prog->len = attr->insn_cnt;

	err = -EFAULT;
	if (copy_from_user(prog->insns, u64_to_user_ptr(attr->insns),
			   bpf_prog_insn_size(prog)) != 0)
		goto free_prog_sec;

	prog->orig_prog = NULL;
	prog->jited = 0;

	atomic64_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = is_gpl ? 1 : 0;

	if (bpf_prog_is_dev_bound(prog->aux)) {
		err = bpf_prog_offload_init(prog, attr);
		if (err)
			goto free_prog_sec;
	}

	 
	err = find_prog_type(type, prog);
	if (err < 0)
		goto free_prog_sec;

	prog->aux->load_time = ktime_get_boottime_ns();
	err = bpf_obj_name_cpy(prog->aux->name, attr->prog_name,
			       sizeof(attr->prog_name));
	if (err < 0)
		goto free_prog_sec;

	 
	err = orbpf_check(&prog, attr, uattr);
	if (err < 0)
		goto free_used_maps;

	prog = bpf_prog_select_runtime(prog, &err);
	if (err < 0)
		goto free_used_maps;

	err = bpf_prog_alloc_id(prog);
	if (err)
		goto free_used_maps;

	













	bpf_prog_kallsyms_add(prog);
	
	bpf_audit_prog(prog, BPF_AUDIT_LOAD);

	if (bpf_jit_enable >= 3)
		bpf_dump_prog_jit_mcode(prog);

	err = bpf_prog_new_fd(prog);
	if (err < 0)
		bpf_prog_put(prog);
	return err;

free_used_maps:
	



	__bpf_prog_put_noref(prog, prog->aux->func_cnt);
	return err;
free_prog_sec:
	free_uid(prog->aux->user);
	security_bpf_prog_free(prog->aux);
free_prog:




	bpf_prog_free(prog);
	return err;
}

#define BPF_OBJ_LAST_FIELD file_flags

static int bpf_obj_pin(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_OBJ) || attr->file_flags != 0)
		return -EINVAL;

	return bpf_obj_pin_user(attr->bpf_fd, u64_to_user_ptr(attr->pathname));
}

static int bpf_obj_get(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_OBJ) || attr->bpf_fd != 0 ||
	    attr->file_flags & ~BPF_OBJ_FLAG_MASK)
		return -EINVAL;

	return bpf_obj_get_user(u64_to_user_ptr(attr->pathname),
				attr->file_flags);
}

void bpf_link_init(struct bpf_link *link, enum bpf_link_type type,
		   const struct bpf_link_ops *ops, struct bpf_prog *prog)
{
	atomic64_set(&link->refcnt, 1);
	link->type = type;
	link->id = 0;
	link->ops = ops;
	link->prog = prog;
}

static void bpf_link_free_id(int id)
{
	if (!id)
		return;

	spin_lock_bh(&link_idr_lock);
	idr_remove(&link_idr, id);
	spin_unlock_bh(&link_idr_lock);
}








void bpf_link_cleanup(struct bpf_link_primer *primer)
{
	primer->link->prog = NULL;
	bpf_link_free_id(primer->id);
	fput(primer->file);
	put_unused_fd(primer->fd);
}

void bpf_link_inc(struct bpf_link *link)
{
	atomic64_inc(&link->refcnt);
}

 
static void bpf_link_free(struct bpf_link *link)
{
	bpf_link_free_id(link->id);
	if (link->prog) {
		 
		link->ops->release(link);
		bpf_prog_put(link->prog);
	}
	 
	link->ops->dealloc(link);
}

static void bpf_link_put_deferred(struct work_struct *work)
{
	struct bpf_link *link = container_of(work, struct bpf_link, work);

	bpf_link_free(link);
}




void bpf_link_put(struct bpf_link *link)
{
	if (!atomic64_dec_and_test(&link->refcnt))
		return;

	if (in_atomic()) {
		INIT_WORK(&link->work, bpf_link_put_deferred);
		schedule_work(&link->work);
	} else {
		bpf_link_free(link);
	}
}

static int bpf_link_release(struct inode *inode, struct file *filp)
{
	struct bpf_link *link = filp->private_data;

	bpf_link_put(link);
	return 0;
}

#ifdef CONFIG_PROC_FS
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type)
#define BPF_MAP_TYPE(_id, _ops)
#define BPF_LINK_TYPE(_id, _name) [_id] = #_name,
static const char *bpf_link_type_strs[] = {
	[BPF_LINK_TYPE_UNSPEC] = "<invalid>",
#include "../../include/linux/bpf_types.h"
};
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE

static void bpf_link_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct bpf_link *link = filp->private_data;
	const struct bpf_prog *prog = link->prog;
	char prog_tag[sizeof(prog->tag) * 2 + 1] = { };

	bin2hex(prog_tag, prog->tag, sizeof(prog->tag));
	seq_printf(m,
		   "link_type:\t%s\n"
		   "link_id:\t%u\n"
		   "prog_tag:\t%s\n"
		   "prog_id:\t%u\n",
		   bpf_link_type_strs[link->type],
		   link->id,
		   prog_tag,
		   prog->aux->id);
	if (link->ops->show_fdinfo)
		link->ops->show_fdinfo(link, m);
}
#endif

static const struct file_operations bpf_link_fops = {
	.owner		= THIS_MODULE,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_link_show_fdinfo,
#endif
	.release	= bpf_link_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
};

static int bpf_link_alloc_id(struct bpf_link *link)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&link_idr_lock);
	id = idr_alloc_cyclic(&link_idr, link, 1, INT_MAX, GFP_ATOMIC);
	spin_unlock_bh(&link_idr_lock);
	idr_preload_end();

	return id;
}














int bpf_link_prime(struct bpf_link *link, struct bpf_link_primer *primer)
{
	struct file *file;
	int fd, id;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;


	id = bpf_link_alloc_id(link);
	if (id < 0) {
		put_unused_fd(fd);
		return id;
	}

	file = anon_inode_getfile("bpf_link", &bpf_link_fops, link, O_CLOEXEC);
	if (IS_ERR(file)) {
		bpf_link_free_id(id);
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	primer->link = link;
	primer->file = file;
	primer->fd = fd;
	primer->id = id;
	return 0;
}

int bpf_link_settle(struct bpf_link_primer *primer)
{
	 
	spin_lock_bh(&link_idr_lock);
	primer->link->id = primer->id;
	spin_unlock_bh(&link_idr_lock);
	 
	fd_install(primer->fd, primer->file);
	 
	return primer->fd;
}

int bpf_link_new_fd(struct bpf_link *link)
{
	return anon_inode_getfd("bpf-link", &bpf_link_fops, link, O_CLOEXEC);
}

struct bpf_link *bpf_link_get_from_fd(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_link *link;

	if (!f.file)
		return ERR_PTR(-EBADF);
	if (f.file->f_op != &bpf_link_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	link = f.file->private_data;
	bpf_link_inc(link);
	fdput(f);

	return link;
}






















































































































































































































































































































































































































static int bpf_prog_attach_check_attach_type(const struct bpf_prog *prog,
					     enum bpf_attach_type attach_type)
{
	switch (prog->type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_SK_LOOKUP:
		return attach_type == prog->expected_attach_type ? 0 : -EINVAL;
	case BPF_PROG_TYPE_CGROUP_SKB:
		if (!capable(CAP_NET_ADMIN))
			


			return -EPERM;
		return prog->enforce_expected_attach_type &&
			prog->expected_attach_type != attach_type ?
			-EINVAL : 0;
	default:
		return 0;
	}
}

static enum bpf_prog_type
attach_type_to_prog_type(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	case BPF_CGROUP_INET_INGRESS:
	case BPF_CGROUP_INET_EGRESS:
		return BPF_PROG_TYPE_CGROUP_SKB;
	case BPF_CGROUP_INET_SOCK_CREATE:
	case BPF_CGROUP_INET_SOCK_RELEASE:
	case BPF_CGROUP_INET4_POST_BIND:
	case BPF_CGROUP_INET6_POST_BIND:
		return BPF_PROG_TYPE_CGROUP_SOCK;
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_INET4_GETPEERNAME:
	case BPF_CGROUP_INET6_GETPEERNAME:
	case BPF_CGROUP_INET4_GETSOCKNAME:
	case BPF_CGROUP_INET6_GETSOCKNAME:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
		return BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
	case BPF_CGROUP_SOCK_OPS:
		return BPF_PROG_TYPE_SOCK_OPS;
	case BPF_CGROUP_DEVICE:
		return BPF_PROG_TYPE_CGROUP_DEVICE;
	case BPF_SK_MSG_VERDICT:
		return BPF_PROG_TYPE_SK_MSG;
	case BPF_SK_SKB_STREAM_PARSER:
	case BPF_SK_SKB_STREAM_VERDICT:
	case BPF_SK_SKB_VERDICT:
		return BPF_PROG_TYPE_SK_SKB;
	case BPF_LIRC_MODE2:
		return BPF_PROG_TYPE_LIRC_MODE2;
	case BPF_FLOW_DISSECTOR:
		return BPF_PROG_TYPE_FLOW_DISSECTOR;
	case BPF_CGROUP_SYSCTL:
		return BPF_PROG_TYPE_CGROUP_SYSCTL;
	case BPF_CGROUP_GETSOCKOPT:
	case BPF_CGROUP_SETSOCKOPT:
		return BPF_PROG_TYPE_CGROUP_SOCKOPT;
	case BPF_TRACE_ITER:
		return BPF_PROG_TYPE_TRACING;
	case BPF_SK_LOOKUP:
		return BPF_PROG_TYPE_SK_LOOKUP;
	case BPF_XDP:
		return BPF_PROG_TYPE_XDP;
	default:
		return BPF_PROG_TYPE_UNSPEC;
	}
}

#define BPF_PROG_ATTACH_LAST_FIELD replace_bpf_fd

#define BPF_F_ATTACH_MASK \
	(BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI | BPF_F_REPLACE)

static int bpf_prog_attach(const union bpf_attr *attr)
{
	enum bpf_prog_type ptype;
	struct bpf_prog *prog;
	int ret;

	if (CHECK_ATTR(BPF_PROG_ATTACH))
		return -EINVAL;

	if (attr->attach_flags & ~BPF_F_ATTACH_MASK)
		return -EINVAL;

	ptype = attach_type_to_prog_type(attr->attach_type);
	if (ptype == BPF_PROG_TYPE_UNSPEC)
		return -EINVAL;

	prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (bpf_prog_attach_check_attach_type(prog, attr->attach_type)) {
		bpf_prog_put(prog);
		return -EINVAL;
	}

	switch (ptype) {
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
		ret = sock_map_get_from_fd(attr, prog);
		break;
	case BPF_PROG_TYPE_LIRC_MODE2:
		ret = lirc_prog_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		ret = netns_bpf_prog_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
		ret = cgroup_bpf_prog_attach(attr, ptype, prog);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		bpf_prog_put(prog);
	return ret;
}

#define BPF_PROG_DETACH_LAST_FIELD attach_type

static int bpf_prog_detach(const union bpf_attr *attr)
{
	enum bpf_prog_type ptype;

	if (CHECK_ATTR(BPF_PROG_DETACH))
		return -EINVAL;

	ptype = attach_type_to_prog_type(attr->attach_type);

	switch (ptype) {
	case BPF_PROG_TYPE_SK_MSG:
	case BPF_PROG_TYPE_SK_SKB:
		return sock_map_prog_detach(attr, ptype);
	case BPF_PROG_TYPE_LIRC_MODE2:
		return lirc_prog_detach(attr);
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		return netns_bpf_prog_detach(attr, ptype);
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
		return cgroup_bpf_prog_detach(attr, ptype);
	default:
		return -EINVAL;
	}
}

#define BPF_PROG_QUERY_LAST_FIELD query.prog_cnt

static int bpf_prog_query(const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (CHECK_ATTR(BPF_PROG_QUERY))
		return -EINVAL;
	if (attr->query.query_flags & ~BPF_F_QUERY_EFFECTIVE)
		return -EINVAL;

	switch (attr->query.attach_type) {
	case BPF_CGROUP_INET_INGRESS:
	case BPF_CGROUP_INET_EGRESS:
	case BPF_CGROUP_INET_SOCK_CREATE:
	case BPF_CGROUP_INET_SOCK_RELEASE:
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET4_POST_BIND:
	case BPF_CGROUP_INET6_POST_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_INET4_GETPEERNAME:
	case BPF_CGROUP_INET6_GETPEERNAME:
	case BPF_CGROUP_INET4_GETSOCKNAME:
	case BPF_CGROUP_INET6_GETSOCKNAME:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
	case BPF_CGROUP_SOCK_OPS:
	case BPF_CGROUP_DEVICE:
	case BPF_CGROUP_SYSCTL:
	case BPF_CGROUP_GETSOCKOPT:
	case BPF_CGROUP_SETSOCKOPT:
		return cgroup_bpf_prog_query(attr, uattr);
	case BPF_LIRC_MODE2:
		return lirc_prog_query(attr, uattr);
	case BPF_FLOW_DISSECTOR:
	case BPF_SK_LOOKUP:
		return netns_bpf_prog_query(attr, uattr);
	default:
		return -EINVAL;
	}
}

#define BPF_PROG_TEST_RUN_LAST_FIELD test.cpu

static int bpf_prog_test_run(const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	struct bpf_prog *prog;
	int ret = -ENOTSUPP;

	if (CHECK_ATTR(BPF_PROG_TEST_RUN))
		return -EINVAL;

	if ((attr->test.ctx_size_in && !attr->test.ctx_in) ||
	    (!attr->test.ctx_size_in && attr->test.ctx_in))
		return -EINVAL;

	if ((attr->test.ctx_size_out && !attr->test.ctx_out) ||
	    (!attr->test.ctx_size_out && attr->test.ctx_out))
		return -EINVAL;

	prog = bpf_prog_get(attr->test.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->aux->ops->test_run)
		ret = prog->aux->ops->test_run(prog, attr, uattr);

	bpf_prog_put(prog);
	return ret;
}

#define BPF_OBJ_GET_NEXT_ID_LAST_FIELD next_id

static int bpf_obj_get_next_id(const union bpf_attr *attr,
			       union bpf_attr __user *uattr,
			       struct idr *idr,
			       spinlock_t *lock)
{
	u32 next_id = attr->start_id;
	int err = 0;

	if (CHECK_ATTR(BPF_OBJ_GET_NEXT_ID) || next_id >= INT_MAX)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	next_id++;
	spin_lock_bh(lock);
	if (!idr_get_next(idr, &next_id))
		err = -ENOENT;
	spin_unlock_bh(lock);

	if (!err)
		err = put_user(next_id, &uattr->next_id);

	return err;
}

struct bpf_map *bpf_map_get_curr_or_next(u32 *id)
{
	struct bpf_map *map;

	spin_lock_bh(&map_idr_lock);
again:
	map = idr_get_next(&map_idr, id);
	if (map) {
		map = __bpf_map_inc_not_zero(map, false);
		if (IS_ERR(map)) {
			(*id)++;
			goto again;
		}
	}
	spin_unlock_bh(&map_idr_lock);

	return map;
}

struct bpf_prog *bpf_prog_get_curr_or_next(u32 *id)
{
	struct bpf_prog *prog;

	spin_lock_bh(&prog_idr_lock);
again:
	prog = idr_get_next(&prog_idr, id);
	if (prog) {
		prog = bpf_prog_inc_not_zero(prog);
		if (IS_ERR(prog)) {
			(*id)++;
			goto again;
		}
	}
	spin_unlock_bh(&prog_idr_lock);

	return prog;
}

#define BPF_PROG_GET_FD_BY_ID_LAST_FIELD prog_id

struct bpf_prog *bpf_prog_by_id(u32 id)
{
	struct bpf_prog *prog;

	if (!id)
		return ERR_PTR(-ENOENT);

	spin_lock_bh(&prog_idr_lock);
	prog = idr_find(&prog_idr, id);
	if (prog)
		prog = bpf_prog_inc_not_zero(prog);
	else
		prog = ERR_PTR(-ENOENT);
	spin_unlock_bh(&prog_idr_lock);
	return prog;
}

static int bpf_prog_get_fd_by_id(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	u32 id = attr->prog_id;
	int fd;

	if (CHECK_ATTR(BPF_PROG_GET_FD_BY_ID))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	prog = bpf_prog_by_id(id);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	fd = bpf_prog_new_fd(prog);
	if (fd < 0)
		bpf_prog_put(prog);

	return fd;
}

#define BPF_MAP_GET_FD_BY_ID_LAST_FIELD open_flags

static int bpf_map_get_fd_by_id(const union bpf_attr *attr)
{
	struct bpf_map *map;
	u32 id = attr->map_id;
	int f_flags;
	int fd;

	if (CHECK_ATTR(BPF_MAP_GET_FD_BY_ID) ||
	    attr->open_flags & ~BPF_OBJ_FLAG_MASK)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	f_flags = bpf_get_file_flag(attr->open_flags);
	if (f_flags < 0)
		return f_flags;

	spin_lock_bh(&map_idr_lock);
	map = idr_find(&map_idr, id);
	if (map)
		map = __bpf_map_inc_not_zero(map, true);
	else
		map = ERR_PTR(-ENOENT);
	spin_unlock_bh(&map_idr_lock);

	if (IS_ERR(map))
		return PTR_ERR(map);

	fd = bpf_map_new_fd(map, f_flags);
	if (fd < 0)
		bpf_map_put_with_uref(map);

	return fd;
}

static const struct bpf_map *bpf_map_from_imm(const struct bpf_prog *prog,
					      unsigned long addr, u32 *off,
					      u32 *type)
{
	const struct bpf_map *map;
	int i;

	mutex_lock(&prog->aux->used_maps_mutex);
	for (i = 0, *off = 0; i < prog->aux->used_map_cnt; i++) {
		map = prog->aux->used_maps[i];
		if (map == (void *)addr) {
			*type = BPF_PSEUDO_MAP_FD;
			goto out;
		}
		if (!map->ops->map_direct_value_meta)
			continue;
		if (!map->ops->map_direct_value_meta(map, addr, off)) {
			*type = BPF_PSEUDO_MAP_VALUE;
			goto out;
		}
	}
	map = NULL;

out:
	mutex_unlock(&prog->aux->used_maps_mutex);
	return map;
}

static struct bpf_insn *bpf_insn_prepare_dump(const struct bpf_prog *prog,
					      const struct cred *f_cred)
{
	const struct bpf_map *map;
	struct bpf_insn *insns;
	u32 off, type;
	u64 imm;
	u8 code;
	int i;

	insns = kmemdup(prog->insnsi, bpf_prog_insn_size(prog),
			GFP_USER);
	if (!insns)
		return insns;

	for (i = 0; i < prog->len; i++) {
		code = insns[i].code;

		if (code == (BPF_JMP | BPF_TAIL_CALL)) {
			insns[i].code = BPF_JMP | BPF_CALL;
			insns[i].imm = BPF_FUNC_tail_call;
			 
		}
		if (code == (BPF_JMP | BPF_CALL) ||
		    code == (BPF_JMP | BPF_CALL_ARGS)) {
			if (code == (BPF_JMP | BPF_CALL_ARGS))
				insns[i].code = BPF_JMP | BPF_CALL;
			if (!bpf_dump_raw_ok(f_cred))
				insns[i].imm = 0;
			continue;
		}
		if (BPF_CLASS(code) == BPF_LDX && BPF_MODE(code) == BPF_PROBE_MEM) {
			insns[i].code = BPF_LDX | BPF_SIZE(code) | BPF_MEM;
			continue;
		}

		if (code != (BPF_LD | BPF_IMM | BPF_DW))
			continue;

		imm = ((u64)insns[i + 1].imm << 32) | (u32)insns[i].imm;
		map = bpf_map_from_imm(prog, imm, &off, &type);
		if (map) {
			insns[i].src_reg = type;
			insns[i].imm = map->id;
			insns[i + 1].imm = off;
			continue;
		}
	}

	return insns;
}

static int set_info_rec_size(struct bpf_prog_info *info)
{
	









	if ((info->nr_func_info || info->func_info_rec_size) &&
	    info->func_info_rec_size != sizeof(struct bpf_func_info))
		return -EINVAL;

	if ((info->nr_line_info || info->line_info_rec_size) &&
	    info->line_info_rec_size != sizeof(struct bpf_line_info))
		return -EINVAL;

	if ((info->nr_jited_line_info || info->jited_line_info_rec_size) &&
	    info->jited_line_info_rec_size != sizeof(__u64))
		return -EINVAL;

	info->func_info_rec_size = sizeof(struct bpf_func_info);
	info->line_info_rec_size = sizeof(struct bpf_line_info);
	info->jited_line_info_rec_size = sizeof(__u64);

	return 0;
}

static int bpf_prog_get_info_by_fd(struct file *file,
				   struct bpf_prog *prog,
				   const union bpf_attr *attr,
				   union bpf_attr __user *uattr)
{
	struct bpf_prog_info __user *uinfo = u64_to_user_ptr(attr->info.info);
	struct bpf_prog_info info;
	u32 info_len = attr->info.info_len;
	struct bpf_prog_stats stats;
	char __user *uinsns;
	u32 ulen;
	int err;

	err = orbpf_check_uarg_tail_zero(uinfo, sizeof(info), info_len);
	if (err)
		return err;
	info_len = min_t(u32, sizeof(info), info_len);

	memset(&info, 0, sizeof(info));
	if (copy_from_user(&info, uinfo, info_len))
		return -EFAULT;

	info.type = prog->type;
	info.id = prog->aux->id;
	info.load_time = prog->aux->load_time;
	info.created_by_uid = from_kuid_munged(current_user_ns(),
					       prog->aux->user->uid);
	info.gpl_compatible = prog->gpl_compatible;

	memcpy(info.tag, prog->tag, sizeof(prog->tag));
	memcpy(info.name, prog->aux->name, sizeof(prog->aux->name));

	mutex_lock(&prog->aux->used_maps_mutex);
	ulen = info.nr_map_ids;
	info.nr_map_ids = prog->aux->used_map_cnt;
	ulen = min_t(u32, info.nr_map_ids, ulen);
	if (ulen) {
		u32 __user *user_map_ids = u64_to_user_ptr(info.map_ids);
		u32 i;

		for (i = 0; i < ulen; i++)
			if (put_user(prog->aux->used_maps[i]->id,
				     &user_map_ids[i])) {
				mutex_unlock(&prog->aux->used_maps_mutex);
				return -EFAULT;
			}
	}
	mutex_unlock(&prog->aux->used_maps_mutex);

	err = set_info_rec_size(&info);
	if (err)
		return err;

	bpf_prog_get_stats(prog, &stats);
	info.run_time_ns = stats.nsecs;
	info.run_cnt = stats.cnt;
	info.recursion_misses = stats.misses;

	if (!bpf_capable()) {
		info.jited_prog_len = 0;
		info.jited_prog_begin_addr = 0;
		info.jited_prog_end_addr = 0;
		info.xlated_prog_len = 0;
		info.nr_jited_ksyms = 0;
		info.nr_jited_func_lens = 0;
		info.nr_func_info = 0;
		info.nr_line_info = 0;
		info.nr_jited_line_info = 0;
		goto done;
	}

	ulen = info.xlated_prog_len;
	info.xlated_prog_len = bpf_prog_insn_size(prog);
	if (info.xlated_prog_len && ulen) {
		struct bpf_insn *insns_sanitized;
		bool fault;

		if (prog->blinded && !bpf_dump_raw_ok(file->f_cred)) {
			info.xlated_prog_insns = 0;
			goto done;
		}
		insns_sanitized = bpf_insn_prepare_dump(prog, file->f_cred);
		if (!insns_sanitized)
			return -ENOMEM;
		uinsns = u64_to_user_ptr(info.xlated_prog_insns);
		ulen = min_t(u32, info.xlated_prog_len, ulen);
		fault = copy_to_user(uinsns, insns_sanitized, ulen);
		kfree(insns_sanitized);
		if (fault)
			return -EFAULT;
	}

	if (bpf_prog_is_dev_bound(prog->aux)) {


#if 1
		err = -ENOTSUPP;
#endif
		if (err)
			return err;
		goto done;
	}

	if (prog->jited) {
		const struct bpf_binary_header *hdr = bpf_jit_binary_hdr(prog);
		info.jited_prog_begin_addr = (unsigned long)hdr;
		info.jited_prog_end_addr = (unsigned long)hdr + hdr->pages * PAGE_SIZE;
	} else {
		info.jited_prog_begin_addr = 0;
		info.jited_prog_end_addr = 0;
	}

	



	ulen = info.jited_prog_len;
	if (prog->aux->func_cnt) {
		u32 i;

		info.jited_prog_len = 0;
		for (i = 0; i < prog->aux->func_cnt; i++)
			info.jited_prog_len += prog->aux->func[i]->jited_len;
	} else {
		info.jited_prog_len = prog->jited_len;
	}

	if (info.jited_prog_len && ulen) {
		if (bpf_dump_raw_ok(file->f_cred)) {
			uinsns = u64_to_user_ptr(info.jited_prog_insns);
			ulen = min_t(u32, info.jited_prog_len, ulen);

			


			if (prog->aux->func_cnt) {
				u32 len, free, i;
				u8 *img;

				free = ulen;
				for (i = 0; i < prog->aux->func_cnt; i++) {
					len = prog->aux->func[i]->jited_len;
					len = min_t(u32, len, free);
					img = (u8 *) prog->aux->func[i]->bpf_func;
					if (copy_to_user(uinsns, img, len))
						return -EFAULT;
					uinsns += len;
					free -= len;
					if (!free)
						break;
				}
			} else {
				if (copy_to_user(uinsns, prog->bpf_func, ulen))
					return -EFAULT;
			}
		} else {
			info.jited_prog_insns = 0;
		}
	}

	ulen = info.nr_jited_ksyms;
	info.nr_jited_ksyms = prog->aux->func_cnt ? : 1;
	if (ulen) {
		if (bpf_dump_raw_ok(file->f_cred)) {
			unsigned long ksym_addr;
			u64 __user *user_ksyms;
			u32 i;

			


			ulen = min_t(u32, info.nr_jited_ksyms, ulen);
			user_ksyms = u64_to_user_ptr(info.jited_ksyms);
			if (prog->aux->func_cnt) {
				for (i = 0; i < ulen; i++) {
					ksym_addr = (unsigned long)
						prog->aux->func[i]->bpf_func;
					if (put_user((u64) ksym_addr,
						     &user_ksyms[i]))
						return -EFAULT;
				}
			} else {
				ksym_addr = (unsigned long) prog->bpf_func;
				if (put_user((u64) ksym_addr, &user_ksyms[0]))
					return -EFAULT;
			}
		} else {
			info.jited_ksyms = 0;
		}
	}

	ulen = info.nr_jited_func_lens;
	info.nr_jited_func_lens = prog->aux->func_cnt ? : 1;
	if (ulen) {
		if (bpf_dump_raw_ok(file->f_cred)) {
			u32 __user *user_lens;
			u32 func_len, i;

			 
			ulen = min_t(u32, info.nr_jited_func_lens, ulen);
			user_lens = u64_to_user_ptr(info.jited_func_lens);
			if (prog->aux->func_cnt) {
				for (i = 0; i < ulen; i++) {
					func_len =
						prog->aux->func[i]->jited_len;
					if (put_user(func_len, &user_lens[i]))
						return -EFAULT;
				}
			} else {
				func_len = prog->jited_len;
				if (put_user(func_len, &user_lens[0]))
					return -EFAULT;
			}
		} else {
			info.jited_func_lens = 0;
		}
	}

	if (prog->aux->btf)
		info.btf_id = btf_obj_id(prog->aux->btf);

	ulen = info.nr_func_info;
	info.nr_func_info = prog->aux->func_info_cnt;
	if (info.nr_func_info && ulen) {
		char __user *user_finfo;

		user_finfo = u64_to_user_ptr(info.func_info);
		ulen = min_t(u32, info.nr_func_info, ulen);
		if (copy_to_user(user_finfo, prog->aux->func_info,
				 info.func_info_rec_size * ulen))
			return -EFAULT;
	}

	ulen = info.nr_line_info;
	info.nr_line_info = prog->aux->nr_linfo;
	if (info.nr_line_info && ulen) {
		__u8 __user *user_linfo;

		user_linfo = u64_to_user_ptr(info.line_info);
		ulen = min_t(u32, info.nr_line_info, ulen);
		if (copy_to_user(user_linfo, prog->aux->linfo,
				 info.line_info_rec_size * ulen))
			return -EFAULT;
	}

	ulen = info.nr_jited_line_info;
	if (prog->aux->jited_linfo)
		info.nr_jited_line_info = prog->aux->nr_linfo;
	else
		info.nr_jited_line_info = 0;
	if (info.nr_jited_line_info && ulen) {
		if (bpf_dump_raw_ok(file->f_cred)) {
			__u64 __user *user_linfo;
			u32 i;

			user_linfo = u64_to_user_ptr(info.jited_line_info);
			ulen = min_t(u32, info.nr_jited_line_info, ulen);
			for (i = 0; i < ulen; i++) {
				if (put_user((__u64)(long)prog->aux->jited_linfo[i],
					     &user_linfo[i]))
					return -EFAULT;
			}
		} else {
			info.jited_line_info = 0;
		}
	}

	ulen = info.nr_prog_tags;
	info.nr_prog_tags = prog->aux->func_cnt ? : 1;
	if (ulen) {
		__u8 __user (*user_prog_tags)[BPF_TAG_SIZE];
		u32 i;

		user_prog_tags = u64_to_user_ptr(info.prog_tags);
		ulen = min_t(u32, info.nr_prog_tags, ulen);
		if (prog->aux->func_cnt) {
			for (i = 0; i < ulen; i++) {
				if (copy_to_user(user_prog_tags[i],
						 prog->aux->func[i]->tag,
						 BPF_TAG_SIZE))
					return -EFAULT;
			}
		} else {
			if (copy_to_user(user_prog_tags[0],
					 prog->tag, BPF_TAG_SIZE))
				return -EFAULT;
		}
	}

done:
	if (copy_to_user(uinfo, &info, info_len) ||
	    put_user(info_len, &uattr->info.info_len))
		return -EFAULT;

	return 0;
}

static int bpf_map_get_info_by_fd(struct file *file,
				  struct bpf_map *map,
				  const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	struct bpf_map_info __user *uinfo = u64_to_user_ptr(attr->info.info);
	struct bpf_map_info info;
	u32 info_len = attr->info.info_len;
	int err;

	err = orbpf_check_uarg_tail_zero(uinfo, sizeof(info), info_len);
	if (err)
		return err;
	info_len = min_t(u32, sizeof(info), info_len);

	memset(&info, 0, sizeof(info));
	info.type = map->map_type;
	info.id = map->id;
	info.key_size = map->key_size;
	info.value_size = map->value_size;
	info.max_entries = map->max_entries;
	info.map_flags = map->map_flags;
	memcpy(info.name, map->name, sizeof(map->name));

	if (map->btf) {
		info.btf_id = btf_obj_id(map->btf);
		info.btf_key_type_id = map->btf_key_type_id;
		info.btf_value_type_id = map->btf_value_type_id;
	}
	info.btf_vmlinux_value_type_id = map->btf_vmlinux_value_type_id;

	if (bpf_map_is_dev_bound(map)) {
		err = -ENOTSUPP;
		return err;
	}

	if (copy_to_user(uinfo, &info, info_len) ||
	    put_user(info_len, &uattr->info.info_len))
		return -EFAULT;

	return 0;
}

static int bpf_btf_get_info_by_fd(struct file *file,
				  struct btf *btf,
				  const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	struct bpf_btf_info __user *uinfo = u64_to_user_ptr(attr->info.info);
	u32 info_len = attr->info.info_len;
	int err;

	err = orbpf_check_uarg_tail_zero(uinfo, sizeof(*uinfo), info_len);
	if (err)
		return err;

	return btf_get_info_by_fd(btf, attr, uattr);
}

static int bpf_link_get_info_by_fd(struct file *file,
				  struct bpf_link *link,
				  const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	struct bpf_link_info __user *uinfo = u64_to_user_ptr(attr->info.info);
	struct bpf_link_info info;
	u32 info_len = attr->info.info_len;
	int err;

	err = orbpf_check_uarg_tail_zero(uinfo, sizeof(info), info_len);
	if (err)
		return err;
	info_len = min_t(u32, sizeof(info), info_len);

	memset(&info, 0, sizeof(info));
	if (copy_from_user(&info, uinfo, info_len))
		return -EFAULT;

	info.type = link->type;
	info.id = link->id;
	info.prog_id = link->prog->aux->id;

	if (link->ops->fill_link_info) {
		err = link->ops->fill_link_info(link, &info);
		if (err)
			return err;
	}

	if (copy_to_user(uinfo, &info, info_len) ||
	    put_user(info_len, &uattr->info.info_len))
		return -EFAULT;

	return 0;
}


#define BPF_OBJ_GET_INFO_BY_FD_LAST_FIELD info.info

static int bpf_obj_get_info_by_fd(const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	int ufd = attr->info.bpf_fd;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_OBJ_GET_INFO_BY_FD))
		return -EINVAL;

	f = fdget(ufd);
	if (!f.file)
		return -EBADFD;

	if (f.file->f_op == &bpf_prog_fops)
		err = bpf_prog_get_info_by_fd(f.file, f.file->private_data, attr,
					      uattr);
	else if (f.file->f_op == &bpf_map_fops)
		err = bpf_map_get_info_by_fd(f.file, f.file->private_data, attr,
					     uattr);
	else if (f.file->f_op == &orbpf_btf_fops)
		err = bpf_btf_get_info_by_fd(f.file, f.file->private_data, attr, uattr);
	else if (f.file->f_op == &bpf_link_fops)
		err = bpf_link_get_info_by_fd(f.file, f.file->private_data,
					      attr, uattr);
	else
		err = -EINVAL;

	fdput(f);
	return err;
}

#define BPF_BTF_LOAD_LAST_FIELD btf_log_level

static int bpf_btf_load(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_BTF_LOAD))
		return -EINVAL;

	if (!bpf_capable())
		return -EPERM;

	return orbpf_btf_new_fd(attr);
}

#define BPF_BTF_GET_FD_BY_ID_LAST_FIELD btf_id

static int bpf_btf_get_fd_by_id(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_BTF_GET_FD_BY_ID))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return btf_get_fd_by_id(attr->btf_id);
}


























































































































#define BPF_MAP_BATCH_LAST_FIELD batch.flags

#define BPF_DO_BATCH(fn)			\
	do {					\
		if (!fn) {			\
			err = -ENOTSUPP;	\
			goto err_put;		\
		}				\
		err = fn(map, attr, uattr);	\
	} while (0)

static int bpf_map_do_batch(const union bpf_attr *attr,
			    union bpf_attr __user *uattr,
			    int cmd)
{
	struct bpf_map *map;
	int err, ufd;
	struct fd f;

	if (CHECK_ATTR(BPF_MAP_BATCH))
		return -EINVAL;

	ufd = attr->batch.map_fd;
	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if ((cmd == BPF_MAP_LOOKUP_BATCH ||
	     cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH) &&
	    !(map_get_sys_perms(map, f) & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	if (cmd != BPF_MAP_LOOKUP_BATCH &&
	    !(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	if (cmd == BPF_MAP_LOOKUP_BATCH)
		BPF_DO_BATCH(map->ops->map_lookup_batch);
	else if (cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH)
		BPF_DO_BATCH(map->ops->map_lookup_and_delete_batch);
	else if (cmd == BPF_MAP_UPDATE_BATCH)
		BPF_DO_BATCH(map->ops->map_update_batch);
	else
		BPF_DO_BATCH(map->ops->map_delete_batch);

err_put:
	fdput(f);
	return err;
}

static int tracing_bpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	if (attr->link_create.attach_type != prog->expected_attach_type)
		return -EINVAL;

	if (prog->expected_attach_type == BPF_TRACE_ITER)
		return bpf_iter_link_attach(attr, prog);






	return -EINVAL;
}

#define BPF_LINK_CREATE_LAST_FIELD link_create.iter_info_len
static int link_create(union bpf_attr *attr)
{
	enum bpf_prog_type ptype;
	struct bpf_prog *prog;
	int ret;

	if (CHECK_ATTR(BPF_LINK_CREATE))
		return -EINVAL;

	prog = bpf_prog_get(attr->link_create.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	ret = bpf_prog_attach_check_attach_type(prog,
						attr->link_create.attach_type);
	if (ret)
		goto out;

	if (prog->type == BPF_PROG_TYPE_EXT) {
		ret = tracing_bpf_link_attach(attr, prog);
		goto out;
	}

	ptype = attach_type_to_prog_type(attr->link_create.attach_type);
	if (ptype == BPF_PROG_TYPE_UNSPEC || ptype != prog->type) {
		ret = -EINVAL;
		goto out;
	}

	switch (ptype) {
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		ret = cgroup_bpf_link_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_TRACING:
		ret = tracing_bpf_link_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_SK_LOOKUP:
		ret = netns_bpf_link_create(attr, prog);
		break;
#ifdef CONFIG_NET
	case BPF_PROG_TYPE_XDP:
		ret = bpf_xdp_link_attach(attr, prog);
		break;
#endif
	default:
		ret = -EINVAL;
	}

out:
	if (ret < 0)
		bpf_prog_put(prog);
	return ret;
}

#define BPF_LINK_UPDATE_LAST_FIELD link_update.old_prog_fd

static int link_update(union bpf_attr *attr)
{
	struct bpf_prog *old_prog = NULL, *new_prog;
	struct bpf_link *link;
	u32 flags;
	int ret;

	if (CHECK_ATTR(BPF_LINK_UPDATE))
		return -EINVAL;

	flags = attr->link_update.flags;
	if (flags & ~BPF_F_REPLACE)
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->link_update.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	new_prog = bpf_prog_get(attr->link_update.new_prog_fd);
	if (IS_ERR(new_prog)) {
		ret = PTR_ERR(new_prog);
		goto out_put_link;
	}

	if (flags & BPF_F_REPLACE) {
		old_prog = bpf_prog_get(attr->link_update.old_prog_fd);
		if (IS_ERR(old_prog)) {
			ret = PTR_ERR(old_prog);
			old_prog = NULL;
			goto out_put_progs;
		}
	} else if (attr->link_update.old_prog_fd) {
		ret = -EINVAL;
		goto out_put_progs;
	}

	if (link->ops->update_prog)
		ret = link->ops->update_prog(link, new_prog, old_prog);
	else
		ret = -EINVAL;

out_put_progs:
	if (old_prog)
		bpf_prog_put(old_prog);
	if (ret)
		bpf_prog_put(new_prog);
out_put_link:
	bpf_link_put(link);
	return ret;
}

#define BPF_LINK_DETACH_LAST_FIELD link_detach.link_fd

static int link_detach(union bpf_attr *attr)
{
	struct bpf_link *link;
	int ret;

	if (CHECK_ATTR(BPF_LINK_DETACH))
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->link_detach.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	if (link->ops->detach)
		ret = link->ops->detach(link);
	else
		ret = -EOPNOTSUPP;

	bpf_link_put(link);
	return ret;
}

static struct bpf_link *bpf_link_inc_not_zero(struct bpf_link *link)
{
	return atomic64_fetch_add_unless(&link->refcnt, 1, 0) ? link : ERR_PTR(-ENOENT);
}

struct bpf_link *bpf_link_by_id(u32 id)
{
	struct bpf_link *link;

	if (!id)
		return ERR_PTR(-ENOENT);

	spin_lock_bh(&link_idr_lock);
	 
	link = idr_find(&link_idr, id);
	if (link) {
		if (link->id)
			link = bpf_link_inc_not_zero(link);
		else
			link = ERR_PTR(-EAGAIN);
	} else {
		link = ERR_PTR(-ENOENT);
	}
	spin_unlock_bh(&link_idr_lock);
	return link;
}

#define BPF_LINK_GET_FD_BY_ID_LAST_FIELD link_id

static int bpf_link_get_fd_by_id(const union bpf_attr *attr)
{
	struct bpf_link *link;
	u32 id = attr->link_id;
	int fd;

	if (CHECK_ATTR(BPF_LINK_GET_FD_BY_ID))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	link = bpf_link_by_id(id);
	if (IS_ERR(link))
		return PTR_ERR(link);

	fd = bpf_link_new_fd(link);
	if (fd < 0)
		bpf_link_put(link);

	return fd;
}

DEFINE_MUTEX(bpf_stats_enabled_mutex);

static int bpf_stats_release(struct inode *inode, struct file *file)
{
	mutex_lock(&bpf_stats_enabled_mutex);
	static_key_slow_dec(&bpf_stats_enabled_key.key);
	mutex_unlock(&bpf_stats_enabled_mutex);
	return 0;
}

static const struct file_operations bpf_stats_fops = {
	.owner = THIS_MODULE,
	.release = bpf_stats_release,
};

static int bpf_enable_runtime_stats(void)
{
	int fd;

	mutex_lock(&bpf_stats_enabled_mutex);

	 
	if (static_key_count(&bpf_stats_enabled_key.key) > INT_MAX / 2) {
		mutex_unlock(&bpf_stats_enabled_mutex);
		return -EBUSY;
	}

	fd = anon_inode_getfd("bpf-stats", &bpf_stats_fops, NULL, O_CLOEXEC);
	if (fd >= 0)
		static_key_slow_inc(&bpf_stats_enabled_key.key);

	mutex_unlock(&bpf_stats_enabled_mutex);
	return fd;
}

#define BPF_ENABLE_STATS_LAST_FIELD enable_stats.type

static int bpf_enable_stats(union bpf_attr *attr)
{

	if (CHECK_ATTR(BPF_ENABLE_STATS))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (attr->enable_stats.type) {
	case BPF_STATS_RUN_TIME:
		return bpf_enable_runtime_stats();
	default:
		break;
	}
	return -EINVAL;
}

#define BPF_ITER_CREATE_LAST_FIELD iter_create.flags

static int bpf_iter_create(union bpf_attr *attr)
{
	struct bpf_link *link;
	int err;

	if (CHECK_ATTR(BPF_ITER_CREATE))
		return -EINVAL;

	if (attr->iter_create.flags)
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->iter_create.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	err = bpf_iter_new_fd(link);
	bpf_link_put(link);

	return err;
}

#define BPF_PROG_BIND_MAP_LAST_FIELD prog_bind_map.flags

static int bpf_prog_bind_map(union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct bpf_map *map;
	struct bpf_map **used_maps_old, **used_maps_new;
	int i, ret = 0;

	if (CHECK_ATTR(BPF_PROG_BIND_MAP))
		return -EINVAL;

	if (attr->prog_bind_map.flags)
		return -EINVAL;

	prog = bpf_prog_get(attr->prog_bind_map.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	map = bpf_map_get(attr->prog_bind_map.map_fd);
	if (IS_ERR(map)) {
		ret = PTR_ERR(map);
		goto out_prog_put;
	}

	mutex_lock(&prog->aux->used_maps_mutex);

	used_maps_old = prog->aux->used_maps;

	for (i = 0; i < prog->aux->used_map_cnt; i++)
		if (used_maps_old[i] == map) {
			bpf_map_put(map);
			goto out_unlock;
		}

	used_maps_new = kmalloc_array(prog->aux->used_map_cnt + 1,
				      sizeof(used_maps_new[0]),
				      GFP_KERNEL);
	if (!used_maps_new) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	memcpy(used_maps_new, used_maps_old,
	       sizeof(used_maps_old[0]) * prog->aux->used_map_cnt);
	used_maps_new[prog->aux->used_map_cnt] = map;

	prog->aux->used_map_cnt++;
	prog->aux->used_maps = used_maps_new;

	kfree(used_maps_old);

out_unlock:
	mutex_unlock(&prog->aux->used_maps_mutex);

	if (ret)
		bpf_map_put(map);
out_prog_put:
	bpf_prog_put(prog);
	return ret;
}

int bpf_syscall(int cmd, union bpf_attr __user *uattr, unsigned int size,
	char __user *prog_label, u32 prog_label_len)
{
	union bpf_attr attr;
	int err;

	if (sysctl_unprivileged_bpf_disabled && !bpf_capable())
		return -EPERM;

	err = orbpf_check_uarg_tail_zero(uattr, sizeof(attr), size);
	if (err)
		return err;
	size = min_t(u32, size, sizeof(attr));

	 
	memset(&attr, 0, sizeof(attr));
	if (copy_from_user(&attr, uattr, size) != 0)
		return -EFAULT;

	err = security_bpf(cmd, &attr, size);
	if (err < 0)
		return err;

	switch (cmd) {
	case BPF_MAP_CREATE:
		err = map_create(&attr);
		break;
	case BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
	case BPF_MAP_UPDATE_ELEM:
		err = map_update_elem(&attr);
		break;
	case BPF_MAP_DELETE_ELEM:
		err = map_delete_elem(&attr);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		err = map_get_next_key(&attr);
		break;
	case BPF_MAP_FREEZE:
		err = map_freeze(&attr);
		break;
	case BPF_PROG_LOAD:
		err = bpf_prog_load(&attr, uattr, prog_label, prog_label_len);
		break;
	case BPF_OBJ_PIN:
		err = bpf_obj_pin(&attr);
		break;
	case BPF_OBJ_GET:
		err = bpf_obj_get(&attr);
		break;
	case BPF_PROG_ATTACH:
		err = bpf_prog_attach(&attr);
		break;
	case BPF_PROG_DETACH:
		err = bpf_prog_detach(&attr);
		break;
	case BPF_PROG_QUERY:
		err = bpf_prog_query(&attr, uattr);
		break;
	case BPF_PROG_TEST_RUN:
		err = bpf_prog_test_run(&attr, uattr);
		break;
	case BPF_PROG_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr,
					  &prog_idr, &prog_idr_lock);
		break;
	case BPF_MAP_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr,
					  &map_idr, &map_idr_lock);
		break;
	case BPF_BTF_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr,
					  orbpf_btf_idr_ptr, orbpf_btf_idr_lock_ptr);
		break;
	case BPF_PROG_GET_FD_BY_ID:
		err = bpf_prog_get_fd_by_id(&attr);
		break;
	case BPF_MAP_GET_FD_BY_ID:
		err = bpf_map_get_fd_by_id(&attr);
		break;
	case BPF_OBJ_GET_INFO_BY_FD:
		err = bpf_obj_get_info_by_fd(&attr, uattr);
		break;





	case BPF_BTF_LOAD:
		err = bpf_btf_load(&attr);
		break;
	case BPF_BTF_GET_FD_BY_ID:
		err = bpf_btf_get_fd_by_id(&attr);
		break;





	case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		err = map_lookup_and_delete_elem(&attr);
		break;
	case BPF_MAP_LOOKUP_BATCH:
		err = bpf_map_do_batch(&attr, uattr, BPF_MAP_LOOKUP_BATCH);
		break;
	case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
		err = bpf_map_do_batch(&attr, uattr,
				       BPF_MAP_LOOKUP_AND_DELETE_BATCH);
		break;
	case BPF_MAP_UPDATE_BATCH:
		err = bpf_map_do_batch(&attr, uattr, BPF_MAP_UPDATE_BATCH);
		break;
	case BPF_MAP_DELETE_BATCH:
		err = bpf_map_do_batch(&attr, uattr, BPF_MAP_DELETE_BATCH);
		break;
	case BPF_LINK_CREATE:
		err = link_create(&attr);
		break;
	case BPF_LINK_UPDATE:
		err = link_update(&attr);
		break;
	case BPF_LINK_GET_FD_BY_ID:
		err = bpf_link_get_fd_by_id(&attr);
		break;
	case BPF_LINK_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr,
					  &link_idr, &link_idr_lock);
		break;
	case BPF_ENABLE_STATS:
		err = bpf_enable_stats(&attr);
		break;
	case BPF_ITER_CREATE:
		err = bpf_iter_create(&attr);
		break;
	case BPF_LINK_DETACH:
		err = link_detach(&attr);
		break;
	case BPF_PROG_BIND_MAP:
		err = bpf_prog_bind_map(&attr);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

int bpf_pcpu_bpf_prog_active_init0(void) { bpf_prog_active = alloc_percpu(int); if (unlikely(bpf_prog_active == NULL)) { return -ENOMEM; } return 0; }
void bpf_pcpu_bpf_prog_active_exit0(void) { free_percpu(bpf_prog_active); }