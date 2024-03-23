/* Copyright (C) by OpenResty Inc. All rights reserved. */



#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/jhash.h>
#include <linux/filter.h>
#include <linux/rculist_nulls.h>
#include <linux/random.h>
#include <uapi/linux/btf.h>
#include <linux/rcupdate_trace.h>
#include <linux/list_sort.h>
#include "percpu_freelist.h"
#include "bpf_lru_list.h"
#include "map_in_map.h"
#include <linux/orbpf_config_begin.h>  

#define HTAB_CREATE_FLAG_MASK						\
	(BPF_F_NO_PREALLOC | BPF_F_NO_COMMON_LRU | BPF_F_NUMA_NODE |	\
	 BPF_F_ACCESS_MASK | BPF_F_ZERO_SEED)

#define BATCH_OPS(_name)			\
	.map_lookup_batch =			\
	_name##_map_lookup_batch,		\
	.map_lookup_and_delete_batch =		\
	_name##_map_lookup_and_delete_batch,	\
	.map_update_batch =			\
	generic_map_update_batch,		\
	.map_delete_batch =			\
	generic_map_delete_batch



















































struct bucket {
	struct hlist_nulls_head head;
	union {
		raw_spinlock_t raw_lock;
		spinlock_t     lock;
	};
};

#define HASHTAB_MAP_LOCK_COUNT 8
#define HASHTAB_MAP_LOCK_MASK (HASHTAB_MAP_LOCK_COUNT - 1)

struct bpf_htab {
	struct bpf_map map;
	struct bucket *buckets;
	void *elems;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	struct htab_elem *__percpu *extra_elems;
	atomic_t count;	 
	u32 n_buckets;	 
	u32 elem_size;	 
	u32 hashrnd;
	struct lock_class_key lockdep_key;
	int __percpu *map_locked[HASHTAB_MAP_LOCK_COUNT];
	struct list_head __percpu *sort_heads;
};

struct htab_sort_node {
	struct htab_elem *list;
	struct list_head next;
};

 
struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct bpf_htab *htab;
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		struct rcu_head rcu;
		struct bpf_lru_node lru_node;
	};
	struct htab_sort_node __percpu *sort_nodes;
	u32 hash;
	char key[] __aligned(8);
};

static inline bool htab_is_prealloc(const struct bpf_htab *htab)
{
	return !(htab->map.map_flags & BPF_F_NO_PREALLOC);
}

static inline bool htab_use_raw_lock(const struct bpf_htab *htab)
{
	return (!IS_ENABLED(CONFIG_PREEMPT_RT) || htab_is_prealloc(htab));
}

static void htab_init_buckets(struct bpf_htab *htab)
{
	unsigned i;

	for (i = 0; i < htab->n_buckets; i++) {
		INIT_HLIST_NULLS_HEAD(&htab->buckets[i].head, i);
		if (htab_use_raw_lock(htab)) {
			raw_spin_lock_init(&htab->buckets[i].raw_lock);
#ifdef ORBPF_CONF_LOCKDEP_REGISTER_KEY
			lockdep_set_class(&htab->buckets[i].raw_lock,
					  &htab->lockdep_key);
#endif
		} else {
			spin_lock_init(&htab->buckets[i].lock);
#ifdef ORBPF_CONF_LOCKDEP_REGISTER_KEY
			lockdep_set_class(&htab->buckets[i].lock,
					  &htab->lockdep_key);
#endif
		}
		cond_resched();
	}
}

static inline int htab_lock_bucket(const struct bpf_htab *htab,
				   struct bucket *b, u32 hash,
				   unsigned long *pflags)
{
	unsigned long flags;

	hash = hash & HASHTAB_MAP_LOCK_MASK;

	migrate_disable();
	if (unlikely(__this_cpu_inc_return(*(htab->map_locked[hash])) != 1)) {
		__this_cpu_dec(*(htab->map_locked[hash]));
		migrate_enable();
		return -EBUSY;
	}

	if (htab_use_raw_lock(htab))
		raw_spin_lock_irqsave(&b->raw_lock, flags);
	else
		spin_lock_irqsave(&b->lock, flags);
	*pflags = flags;

	return 0;
}

static inline void htab_unlock_bucket(const struct bpf_htab *htab,
				      struct bucket *b, u32 hash,
				      unsigned long flags)
{
	hash = hash & HASHTAB_MAP_LOCK_MASK;
	if (htab_use_raw_lock(htab))
		raw_spin_unlock_irqrestore(&b->raw_lock, flags);
	else
		spin_unlock_irqrestore(&b->lock, flags);
	__this_cpu_dec(*(htab->map_locked[hash]));
	migrate_enable();
}

static bool htab_lru_map_delete_node(void *arg, struct bpf_lru_node *node);

static bool htab_is_lru(const struct bpf_htab *htab)
{
	return htab->map.map_type == BPF_MAP_TYPE_LRU_HASH ||
		htab->map.map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static bool htab_is_percpu(const struct bpf_htab *htab)
{
	return htab->map.map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		htab->map.map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static inline void htab_elem_set_ptr(struct htab_elem *l, u32 key_size,
				     void __percpu *pptr)
{
	*(void __percpu **)(l->key + key_size) = pptr;
}

static inline void __percpu *htab_elem_get_ptr(struct htab_elem *l, u32 key_size)
{
	return *(void __percpu **)(l->key + key_size);
}

static void *fd_htab_map_get_ptr(const struct bpf_map *map, struct htab_elem *l)
{
	return *(void **)(l->key + roundup(map->key_size, 8));
}

static struct htab_elem *get_htab_elem(struct bpf_htab *htab, int i)
{
	return (struct htab_elem *) (htab->elems + i * (u64)htab->elem_size);
}

static void htab_free_elems(struct bpf_htab *htab)
{
	int i;

	for (i = 0; i < htab->map.max_entries; i++)
		free_percpu(get_htab_elem(htab, i)->sort_nodes);

	if (!htab_is_percpu(htab))
		goto free_elems;

	for (i = 0; i < htab->map.max_entries; i++) {
		void __percpu *pptr;

		pptr = htab_elem_get_ptr(get_htab_elem(htab, i),
					 htab->map.key_size);
		free_percpu(pptr);
		cond_resched();
	}
free_elems:
	bpf_map_area_free(htab->elems);
}












static struct htab_elem *prealloc_lru_pop(struct bpf_htab *htab, void *key,
					  u32 hash)
{
	struct bpf_lru_node *node = bpf_lru_pop_free(&htab->lru, hash);
	struct htab_elem *l;

	if (node) {
		l = container_of(node, struct htab_elem, lru_node);
		memcpy(l->key, key, htab->map.key_size);
		return l;
	}

	return NULL;
}

static void sort_nodes_init(struct htab_elem *l)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu)
		per_cpu_ptr(l->sort_nodes, cpu)->list = l;
}

static int prealloc_init(struct bpf_htab *htab)
{
	u32 num_entries = htab->map.max_entries;
	int err = -ENOMEM, i;

	if (!htab_is_percpu(htab) && !htab_is_lru(htab))
		num_entries += num_possible_cpus();

	htab->elems = bpf_map_area_alloc((u64)htab->elem_size * num_entries,
					 htab->map.numa_node);
	if (!htab->elems)
		return -ENOMEM;

	if (!htab_is_percpu(htab))
		goto skip_percpu_elems;

	for (i = 0; i < num_entries; i++) {
		u32 size = round_up(htab->map.value_size, 8);
		void __percpu *pptr;

		pptr = bpf_map_alloc_percpu(&htab->map, size, 8,
					    GFP_USER | __GFP_NOWARN);
		if (!pptr)
			goto free_elems;
		htab_elem_set_ptr(get_htab_elem(htab, i), htab->map.key_size,
				  pptr);
		cond_resched();
	}

skip_percpu_elems:
	for (i = 0; i < num_entries; i++) {
		struct htab_elem *l = get_htab_elem(htab, i);

		l->sort_nodes = bpf_map_alloc_percpu(&htab->map,
						sizeof(*l->sort_nodes), 8,
						GFP_USER | __GFP_NOWARN);
		if (!l->sort_nodes)
			goto free_elems;

		sort_nodes_init(l);
	}

	if (htab_is_lru(htab))
		err = bpf_lru_init(&htab->lru,
				   htab->map.map_flags & BPF_F_NO_COMMON_LRU,
				   offsetof(struct htab_elem, hash) -
				   offsetof(struct htab_elem, lru_node),
				   htab_lru_map_delete_node,
				   htab);
	else
		err = pcpu_freelist_init(&htab->freelist);

	if (err)
		goto free_elems;

	if (htab_is_lru(htab))
		bpf_lru_populate(&htab->lru, htab->elems,
				 offsetof(struct htab_elem, lru_node),
				 htab->elem_size, num_entries);
	else
		pcpu_freelist_populate(&htab->freelist,
				       htab->elems + offsetof(struct htab_elem, fnode),
				       htab->elem_size, num_entries);

	return 0;

free_elems:
	htab_free_elems(htab);
	return err;
}

static void prealloc_destroy(struct bpf_htab *htab)
{
	htab_free_elems(htab);

	if (htab_is_lru(htab))
		bpf_lru_destroy(&htab->lru);
	else
		pcpu_freelist_destroy(&htab->freelist);
}

static int alloc_extra_elems(struct bpf_htab *htab)
{
	struct htab_elem *__percpu *pptr, *l_new;
	struct pcpu_freelist_node *l;
	int cpu;

	pptr = bpf_map_alloc_percpu(&htab->map, sizeof(struct htab_elem *), 8,
				    GFP_USER | __GFP_NOWARN);
	if (!pptr)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		l = pcpu_freelist_pop(&htab->freelist);
		


		l_new = container_of(l, struct htab_elem, fnode);
		*per_cpu_ptr(pptr, cpu) = l_new;
	}
	htab->extra_elems = pptr;
	return 0;
}

 
static int htab_map_alloc_check(union bpf_attr *attr)
{
	bool percpu = (attr->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		       attr->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH);
	bool lru = (attr->map_type == BPF_MAP_TYPE_LRU_HASH ||
		    attr->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH);
	




	bool percpu_lru = (attr->map_flags & BPF_F_NO_COMMON_LRU);
	bool prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);
	bool zero_seed = (attr->map_flags & BPF_F_ZERO_SEED);
	int numa_node = bpf_map_attr_numa_node(attr);

	BUILD_BUG_ON(offsetof(struct htab_elem, htab) !=
		     offsetof(struct htab_elem, hash_node.pprev));
	BUILD_BUG_ON(offsetof(struct htab_elem, fnode.next) !=
		     offsetof(struct htab_elem, hash_node.pprev));

	if (lru && !bpf_capable())
		


		return -EPERM;

	if (zero_seed && !capable(CAP_SYS_ADMIN))
		 
		return -EPERM;

	if (attr->map_flags & ~HTAB_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (!lru && percpu_lru)
		return -EINVAL;

	if (lru && !prealloc)
		return -ENOTSUPP;

	if (numa_node != NUMA_NO_NODE && (percpu || percpu_lru))
		return -EINVAL;

	


	if (attr->max_entries == 0 || attr->key_size == 0 ||
	    attr->value_size == 0)
		return -EINVAL;

	if ((u64)attr->key_size + attr->value_size >= KMALLOC_MAX_SIZE -
	   sizeof(struct htab_elem))
		




		return -E2BIG;

	return 0;
}

static struct bpf_map *htab_map_alloc(union bpf_attr *attr)
{
	bool percpu = (attr->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		       attr->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH);
	bool lru = (attr->map_type == BPF_MAP_TYPE_LRU_HASH ||
		    attr->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH);
	




	bool percpu_lru = (attr->map_flags & BPF_F_NO_COMMON_LRU);
	bool prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);
	struct bpf_htab *htab;
	int err, i;

	htab = kzalloc(sizeof(*htab), GFP_USER | __GFP_ACCOUNT);
	if (!htab)
		return ERR_PTR(-ENOMEM);

	lockdep_register_key(&htab->lockdep_key);

	bpf_map_init_from_attr(&htab->map, attr);

	if (percpu_lru) {
		



		htab->map.max_entries = roundup(attr->max_entries,
						num_possible_cpus());
		if (htab->map.max_entries < attr->max_entries)
			htab->map.max_entries = rounddown(attr->max_entries,
							  num_possible_cpus());
	}

	 
	htab->n_buckets = roundup_pow_of_two(htab->map.max_entries);

	htab->elem_size = sizeof(struct htab_elem) +
			  round_up(htab->map.key_size, 8);
	if (percpu)
		htab->elem_size += sizeof(void *);
	else
		htab->elem_size += round_up(htab->map.value_size, 8);

	err = -E2BIG;
	 
	if (htab->n_buckets == 0 ||
	    htab->n_buckets > U32_MAX / sizeof(struct bucket))
		goto free_htab;

	err = -ENOMEM;
	htab->buckets = bpf_map_area_alloc(htab->n_buckets *
					   sizeof(struct bucket),
					   htab->map.numa_node);
	if (!htab->buckets)
		goto free_htab;

	for (i = 0; i < HASHTAB_MAP_LOCK_COUNT; i++) {
		htab->map_locked[i] = bpf_map_alloc_percpu(&htab->map,
							   sizeof(int),
							   sizeof(int),
							   GFP_USER);
		if (!htab->map_locked[i])
			goto free_map_locked;
	}

	htab->sort_heads = bpf_map_alloc_percpu(&htab->map,
						sizeof(struct list_head), 8,
						GFP_USER);
	if (!htab->sort_heads)
		goto free_map_locked;

	if (htab->map.map_flags & BPF_F_ZERO_SEED)
		htab->hashrnd = 0;
	else
		htab->hashrnd = get_random_int();

	htab_init_buckets(htab);

	if (prealloc) {
		err = prealloc_init(htab);
		if (err)
			goto free_sort_heads;

		if (!percpu && !lru) {
			


			err = alloc_extra_elems(htab);
			if (err)
				goto free_prealloc;
		}
	}

	return &htab->map;

free_prealloc:
	prealloc_destroy(htab);
free_sort_heads:
	free_percpu(htab->sort_heads);
free_map_locked:
	for (i = 0; i < HASHTAB_MAP_LOCK_COUNT; i++)
		free_percpu(htab->map_locked[i]);
	bpf_map_area_free(htab->buckets);
free_htab:
	lockdep_unregister_key(&htab->lockdep_key);
	kfree(htab);
	return ERR_PTR(err);
}

static inline u32 htab_map_hash(const void *key, u32 key_len, u32 hashrnd)
{
	return jhash(key, key_len, hashrnd);
}

static inline struct bucket *__select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static inline struct hlist_nulls_head *select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

 
static struct htab_elem *lookup_elem_raw(struct hlist_nulls_head *head, u32 hash,
					 void *key, u32 key_size)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;

	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;

	return NULL;
}





static struct htab_elem *lookup_nulls_elem_raw(struct hlist_nulls_head *head,
					       u32 hash, void *key,
					       u32 key_size, u32 n_buckets)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;

again:
	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;

	if (unlikely(get_nulls_value(n) != (hash & (n_buckets - 1))))
		goto again;

	return NULL;
}






static void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l;
	u32 hash, key_size;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	head = select_bucket(htab, hash);

	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	return l;
}

static void *htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct htab_elem *l = __htab_map_lookup_elem(map, key);

	if (l)
		return l->key + round_up(map->key_size, 8);

	return NULL;
}












static


#if 1
int
#endif
htab_map_gen_lookup(struct bpf_map *map, struct bpf_insn *insn_buf)
{
	struct bpf_insn *insn = insn_buf;
	const int ret = BPF_REG_0;

	BUILD_BUG_ON(!__same_type(&__htab_map_lookup_elem,
		     (void *(*)(struct bpf_map *map, void *key))NULL));
	*insn++ = BPF_EMIT_CALL(BPF_CAST_CALL(__htab_map_lookup_elem));
	*insn++ = BPF_JMP_IMM(BPF_JEQ, ret, 0, 1);
	*insn++ = BPF_ALU64_IMM(BPF_ADD, ret,
				offsetof(struct htab_elem, key) +
				round_up(map->key_size, 8));
	return insn - insn_buf;
}

static __always_inline void *__htab_lru_map_lookup_elem(struct bpf_map *map,
							void *key, const bool mark)
{
	struct htab_elem *l = __htab_map_lookup_elem(map, key);

	if (l) {
		if (mark)
			bpf_lru_node_set_ref(&l->lru_node);
		return l->key + round_up(map->key_size, 8);
	}

	return NULL;
}

static void *htab_lru_map_lookup_elem(struct bpf_map *map, void *key)
{
	return __htab_lru_map_lookup_elem(map, key, true);
}

#if 1
static void *htab_lru_map_lookup_elem_sys(struct bpf_map *map, void *key)
{
	return __htab_lru_map_lookup_elem(map, key, false);
}
#endif

static


#if 1
int
#endif
htab_lru_map_gen_lookup(struct bpf_map *map,
				   struct bpf_insn *insn_buf)
{
	struct bpf_insn *insn = insn_buf;
	const int ret = BPF_REG_0;
	const int ref_reg = BPF_REG_1;

	BUILD_BUG_ON(!__same_type(&__htab_map_lookup_elem,
		     (void *(*)(struct bpf_map *map, void *key))NULL));
	*insn++ = BPF_EMIT_CALL(BPF_CAST_CALL(__htab_map_lookup_elem));
	*insn++ = BPF_JMP_IMM(BPF_JEQ, ret, 0, 4);
	*insn++ = BPF_LDX_MEM(BPF_B, ref_reg, ret,
			      offsetof(struct htab_elem, lru_node) +
			      offsetof(struct bpf_lru_node, ref));
	*insn++ = BPF_JMP_IMM(BPF_JNE, ref_reg, 0, 1);
	*insn++ = BPF_ST_MEM(BPF_B, ret,
			     offsetof(struct htab_elem, lru_node) +
			     offsetof(struct bpf_lru_node, ref),
			     1);
	*insn++ = BPF_ALU64_IMM(BPF_ADD, ret,
				offsetof(struct htab_elem, key) +
				round_up(map->key_size, 8));
	return insn - insn_buf;
}




static bool htab_lru_map_delete_node(void *arg, struct bpf_lru_node *node)
{
	struct bpf_htab *htab = (struct bpf_htab *)arg;
	struct htab_elem *l = NULL, *tgt_l;
	struct hlist_nulls_head *head;
	struct hlist_nulls_node *n;
	unsigned long flags;
	struct bucket *b;
	int ret;

	tgt_l = container_of(node, struct htab_elem, lru_node);
	b = __select_bucket(htab, tgt_l->hash);
	head = &b->head;

	ret = htab_lock_bucket(htab, b, tgt_l->hash, &flags);
	if (ret)
		return false;

	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l == tgt_l) {
			hlist_nulls_del_rcu(&l->hash_node);
			break;
		}

	htab_unlock_bucket(htab, b, tgt_l->hash, flags);

	return l == tgt_l;
}

 
static int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l, *next_l;
	u32 hash, key_size;
	int i = 0;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	if (!key)
		goto find_first_elem;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	head = select_bucket(htab, hash);

	 
	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	if (!l)
		goto find_first_elem;

	 
	next_l = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_next_rcu(&l->hash_node)),
				  struct htab_elem, hash_node);

	if (next_l) {
		 
		memcpy(next_key, next_l->key, key_size);
		return 0;
	}

	 
	i = hash & (htab->n_buckets - 1);
	i++;

find_first_elem:
	 
	for (; i < htab->n_buckets; i++) {
		head = select_bucket(htab, i);

		 
		next_l = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_first_rcu(head)),
					  struct htab_elem, hash_node);
		if (next_l) {
			 
			memcpy(next_key, next_l->key, key_size);
			return 0;
		}
	}

	 
	return -ENOENT;
}

static void htab_elem_free(struct bpf_htab *htab, struct htab_elem *l)
{
	if (htab->map.map_type == BPF_MAP_TYPE_PERCPU_HASH)
		free_percpu(htab_elem_get_ptr(l, htab->map.key_size));
	free_percpu(l->sort_nodes);
	kfree(l);
}

static void htab_elem_free_rcu(struct rcu_head *head)
{
	struct htab_elem *l = container_of(head, struct htab_elem, rcu);
	struct bpf_htab *htab = l->htab;

	htab_elem_free(htab, l);
}

static void htab_put_fd_value(struct bpf_htab *htab, struct htab_elem *l)
{
	struct bpf_map *map = &htab->map;
	void *ptr;

	if (map->ops->map_fd_put_ptr) {
		ptr = fd_htab_map_get_ptr(map, l);
		map->ops->map_fd_put_ptr(ptr);
	}
}

static void free_htab_elem(struct bpf_htab *htab, struct htab_elem *l)
{
	htab_put_fd_value(htab, l);

	if (htab_is_prealloc(htab)) {
		__pcpu_freelist_push(&htab->freelist, &l->fnode);
	} else {
		atomic_dec(&htab->count);
		l->htab = htab;
		call_rcu(&l->rcu, htab_elem_free_rcu);
	}
}

static void pcpu_copy_value(struct bpf_htab *htab, void __percpu *pptr,
			    void *value, bool onallcpus, bool allsameval)
{
	if (!onallcpus) {
		 
		memcpy(this_cpu_ptr(pptr), value, htab->map.value_size);
	} else {
		u32 size = round_up(htab->map.value_size, 8);
		int off = 0, cpu;

		for_each_possible_cpu(cpu) {
			bpf_long_memcpy(per_cpu_ptr(pptr, cpu),
					value + off, size);
			if (!allsameval)
				off += size;
		}
	}
}

static void pcpu_init_value(struct bpf_htab *htab, void __percpu *pptr,
			    void *value, bool onallcpus, bool allsameval)
{
	





	if (htab_is_prealloc(htab) && !onallcpus) {
		u32 size = round_up(htab->map.value_size, 8);
		int current_cpu = raw_smp_processor_id();
		int cpu;

		for_each_possible_cpu(cpu) {
			if (cpu == current_cpu)
				bpf_long_memcpy(per_cpu_ptr(pptr, cpu), value,
						size);
			else
				memset(per_cpu_ptr(pptr, cpu), 0, size);
		}
	} else {
		pcpu_copy_value(htab, pptr, value, onallcpus, allsameval);
	}
}

static bool fd_htab_map_needs_adjust(const struct bpf_htab *htab)
{
	return htab->map.map_type == BPF_MAP_TYPE_HASH_OF_MAPS &&
	       BITS_PER_LONG == 64;
}

static struct htab_elem *alloc_htab_elem(struct bpf_htab *htab, void *key,
					 void *value, u32 key_size, u32 hash,
					 bool percpu, bool onallcpus,
					 struct htab_elem *old_elem,
					 bool allsameval)
{
	u32 size = htab->map.value_size;
	bool prealloc = htab_is_prealloc(htab);
	struct htab_elem *l_new, **pl_new;
	void __percpu *pptr;

	if (prealloc) {
		if (old_elem) {
			


			pl_new = this_cpu_ptr(htab->extra_elems);
			l_new = *pl_new;
			htab_put_fd_value(htab, old_elem);
			*pl_new = old_elem;
		} else {
			struct pcpu_freelist_node *l;

			l = __pcpu_freelist_pop(&htab->freelist);
			if (!l)
				return ERR_PTR(-E2BIG);
			l_new = container_of(l, struct htab_elem, fnode);
		}
	} else {
		if (atomic_inc_return(&htab->count) > htab->map.max_entries)
			if (!old_elem) {
				




				l_new = ERR_PTR(-E2BIG);
				goto dec_count;
			}
		l_new = bpf_map_kmalloc_node(&htab->map, htab->elem_size,
					     GFP_ATOMIC | __GFP_NOWARN,
					     htab->map.numa_node);
		if (!l_new) {
			l_new = ERR_PTR(-ENOMEM);
			goto dec_count;
		}
		l_new->sort_nodes = bpf_map_alloc_percpu(&htab->map,
						sizeof(*l_new->sort_nodes), 8,
						GFP_ATOMIC | __GFP_NOWARN);
		if (!l_new->sort_nodes) {
			kfree(l_new);
			l_new = ERR_PTR(-ENOMEM);
			goto dec_count;
		}
		sort_nodes_init(l_new);
		orbpf_check_and_init_map_lock(&htab->map,
					l_new->key + round_up(key_size, 8));
	}

	memcpy(l_new->key, key, key_size);
	if (percpu) {
		size = round_up(size, 8);
		if (prealloc) {
			pptr = htab_elem_get_ptr(l_new, key_size);
		} else {
			 
			pptr = bpf_map_alloc_percpu(&htab->map, size, 8,
						    GFP_ATOMIC | __GFP_NOWARN);
			if (!pptr) {
				free_percpu(l_new->sort_nodes);
				kfree(l_new);
				l_new = ERR_PTR(-ENOMEM);
				goto dec_count;
			}
		}

		pcpu_init_value(htab, pptr, value, onallcpus, allsameval);

		if (!prealloc)
			htab_elem_set_ptr(l_new, key_size, pptr);
	} else if (fd_htab_map_needs_adjust(htab)) {
		size = round_up(size, 8);
		memcpy(l_new->key + round_up(key_size, 8), value, size);
	} else {
		orbpf_copy_map_value(&htab->map,
			       l_new->key + round_up(key_size, 8),
			       value);
	}

	l_new->hash = hash;
	return l_new;
dec_count:
	atomic_dec(&htab->count);
	return l_new;
}

static int check_flags(struct bpf_htab *htab, struct htab_elem *l_old,
		       u64 map_flags)
{
	if (l_old && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		 
		return -EEXIST;

	if (!l_old && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		 
		return -ENOENT;

	return 0;
}

 
static int htab_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new = NULL, *l_old;
	struct hlist_nulls_head *head;
	unsigned long flags;
	struct bucket *b;
	u32 key_size, hash;
	int ret;

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		 
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	b = __select_bucket(htab, hash);
	head = &b->head;

	if (unlikely(map_flags & BPF_F_LOCK)) {
		if (unlikely(!orbpf_map_value_has_spin_lock(map)))
			return -EINVAL;
		 
		l_old = lookup_nulls_elem_raw(head, hash, key, key_size,
					      htab->n_buckets);
		ret = check_flags(htab, l_old, map_flags);
		if (ret)
			return ret;
		if (l_old) {
			 
			orbpf_copy_map_value_locked(map,
					      l_old->key + round_up(key_size, 8),
					      value, false);
			return 0;
		}
		



	}

	ret = htab_lock_bucket(htab, b, hash, &flags);
	if (ret)
		return ret;

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(htab, l_old, map_flags);
	if (ret)
		goto err;

	if (unlikely(l_old && (map_flags & BPF_F_LOCK))) {
		





		orbpf_copy_map_value_locked(map,
				      l_old->key + round_up(key_size, 8),
				      value, false);
		ret = 0;
		goto err;
	}

	l_new = alloc_htab_elem(htab, key, value, key_size, hash, false, false,
				l_old, false);
	if (IS_ERR(l_new)) {
		 
		ret = PTR_ERR(l_new);
		goto err;
	}

	


	hlist_nulls_add_head_rcu(&l_new->hash_node, head);
	if (l_old) {
		hlist_nulls_del_rcu(&l_old->hash_node);
		if (!htab_is_prealloc(htab))
			free_htab_elem(htab, l_old);
	}
	ret = 0;
err:
	htab_unlock_bucket(htab, b, hash, flags);
	return ret;
}

static int htab_lru_map_update_elem(struct bpf_map *map, void *key, void *value,
				    u64 map_flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new, *l_old = NULL;
	struct hlist_nulls_head *head;
	unsigned long flags;
	struct bucket *b;
	u32 key_size, hash;
	int ret;

	if (unlikely(map_flags > BPF_EXIST))
		 
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	b = __select_bucket(htab, hash);
	head = &b->head;

	




	l_new = prealloc_lru_pop(htab, key, hash);
	if (!l_new)
		return -ENOMEM;
	memcpy(l_new->key + round_up(map->key_size, 8), value, map->value_size);

	ret = htab_lock_bucket(htab, b, hash, &flags);
	if (ret)
		return ret;

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(htab, l_old, map_flags);
	if (ret)
		goto err;

	


	hlist_nulls_add_head_rcu(&l_new->hash_node, head);
	if (l_old) {
		bpf_lru_node_set_ref(&l_new->lru_node);
		hlist_nulls_del_rcu(&l_old->hash_node);
	}
	ret = 0;

err:
	htab_unlock_bucket(htab, b, hash, flags);

	if (ret)
		bpf_lru_push_free(&htab->lru, &l_new->lru_node);
	else if (l_old)
		bpf_lru_push_free(&htab->lru, &l_old->lru_node);

	return ret;
}

static int __htab_percpu_map_update_elem(struct bpf_map *map, void *key,
					 void *value, u64 map_flags,
					 bool onallcpus, bool allsameval)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new = NULL, *l_old;
	struct hlist_nulls_head *head;
	unsigned long flags;
	struct bucket *b;
	u32 key_size, hash;
	int ret;

	if (unlikely(map_flags > BPF_EXIST))
		 
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	b = __select_bucket(htab, hash);
	head = &b->head;

	ret = htab_lock_bucket(htab, b, hash, &flags);
	if (ret)
		return ret;

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(htab, l_old, map_flags);
	if (ret)
		goto err;

	if (l_old) {
		 
		pcpu_copy_value(htab, htab_elem_get_ptr(l_old, key_size),
				value, onallcpus, allsameval);
	} else {
		l_new = alloc_htab_elem(htab, key, value, key_size,
					hash, true, onallcpus, NULL,
					allsameval);
		if (IS_ERR(l_new)) {
			ret = PTR_ERR(l_new);
			goto err;
		}
		hlist_nulls_add_head_rcu(&l_new->hash_node, head);
	}
	ret = 0;
err:
	htab_unlock_bucket(htab, b, hash, flags);
	return ret;
}

static int __htab_lru_percpu_map_update_elem(struct bpf_map *map, void *key,
					     void *value, u64 map_flags,
					     bool onallcpus, bool allsameval)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new = NULL, *l_old;
	struct hlist_nulls_head *head;
	unsigned long flags;
	struct bucket *b;
	u32 key_size, hash;
	int ret;

	if (unlikely(map_flags > BPF_EXIST))
		 
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	b = __select_bucket(htab, hash);
	head = &b->head;

	




	if (map_flags != BPF_EXIST) {
		l_new = prealloc_lru_pop(htab, key, hash);
		if (!l_new)
			return -ENOMEM;
	}

	ret = htab_lock_bucket(htab, b, hash, &flags);
	if (ret)
		return ret;

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(htab, l_old, map_flags);
	if (ret)
		goto err;

	if (l_old) {
		bpf_lru_node_set_ref(&l_old->lru_node);

		 
		pcpu_copy_value(htab, htab_elem_get_ptr(l_old, key_size),
				value, onallcpus, allsameval);
	} else {
		pcpu_init_value(htab, htab_elem_get_ptr(l_new, key_size),
				value, onallcpus, allsameval);
		hlist_nulls_add_head_rcu(&l_new->hash_node, head);
		l_new = NULL;
	}
	ret = 0;
err:
	htab_unlock_bucket(htab, b, hash, flags);
	if (l_new)
		bpf_lru_push_free(&htab->lru, &l_new->lru_node);
	return ret;
}

static int htab_percpu_map_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags)
{
	return __htab_percpu_map_update_elem(map, key, value, map_flags, false,
					     false);
}

static int htab_lru_percpu_map_update_elem(struct bpf_map *map, void *key,
					   void *value, u64 map_flags)
{
	return __htab_lru_percpu_map_update_elem(map, key, value, map_flags,
						 false, false);
}

 
static int htab_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct bucket *b;
	struct htab_elem *l;
	unsigned long flags;
	u32 hash, key_size;
	int ret;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);
	b = __select_bucket(htab, hash);
	head = &b->head;

	ret = htab_lock_bucket(htab, b, hash, &flags);
	if (ret)
		return ret;

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l) {
		hlist_nulls_del_rcu(&l->hash_node);
		free_htab_elem(htab, l);
	} else {
		ret = -ENOENT;
	}

	htab_unlock_bucket(htab, b, hash, flags);
	return ret;
}

int htab_map_clear(struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	u32 hash;

	 
	for (hash = 0; hash < htab->n_buckets; hash++) {
		struct bucket *b = &htab->buckets[hash];
		struct hlist_nulls_head *head = &b->head;
		struct hlist_nulls_node *n;
		struct htab_elem *l;
		unsigned long flags;
		int ret;

		ret = htab_lock_bucket(htab, b, hash, &flags);
		if (ret)
			return ret;

		hlist_nulls_for_each_entry_rcu(l, n, head, hash_node) {
			hlist_nulls_del_rcu(&l->hash_node);
			free_htab_elem(htab, l);
		}
		htab_unlock_bucket(htab, b, hash, flags);
	}

	return 0;
}

static int htab_lru_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct bucket *b;
	struct htab_elem *l;
	unsigned long flags;
	u32 hash, key_size;
	int ret;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);
	b = __select_bucket(htab, hash);
	head = &b->head;

	ret = htab_lock_bucket(htab, b, hash, &flags);
	if (ret)
		return ret;

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l)
		hlist_nulls_del_rcu(&l->hash_node);
	else
		ret = -ENOENT;

	htab_unlock_bucket(htab, b, hash, flags);
	if (l)
		bpf_lru_push_free(&htab->lru, &l->lru_node);
	return ret;
}

static void delete_all_elements(struct bpf_htab *htab)
{
	int i;

	for (i = 0; i < htab->n_buckets; i++) {
		struct hlist_nulls_head *head = select_bucket(htab, i);
		struct hlist_nulls_node *n;
		struct htab_elem *l;

		hlist_nulls_for_each_entry_safe(l, n, head, hash_node) {
			hlist_nulls_del_rcu(&l->hash_node);
			htab_elem_free(htab, l);
		}
	}
}

 
static void htab_map_free(struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	int i;

	




	


	rcu_barrier();
	if (!htab_is_prealloc(htab))
		delete_all_elements(htab);
	else
		prealloc_destroy(htab);

	free_percpu(htab->sort_heads);
	free_percpu(htab->extra_elems);
	bpf_map_area_free(htab->buckets);
	for (i = 0; i < HASHTAB_MAP_LOCK_COUNT; i++)
		free_percpu(htab->map_locked[i]);
	lockdep_unregister_key(&htab->lockdep_key);
	kfree(htab);
}

static void htab_map_seq_show_elem(struct bpf_map *map, void *key,
				   struct seq_file *m)
{
	void *value;

	rcu_read_lock();

	value = htab_map_lookup_elem(map, key);
	if (!value) {
		rcu_read_unlock();
		return;
	}

	btf_type_seq_show(map->btf, map->btf_key_type_id, key, m);
	seq_puts(m, ": ");
	btf_type_seq_show(map->btf, map->btf_value_type_id, value, m);
	seq_puts(m, "\n");

	rcu_read_unlock();
}

#if 1
static int
__htab_map_lookup_and_delete_batch(struct bpf_map *map,
				   const union bpf_attr *attr,
				   union bpf_attr __user *uattr,
				   bool do_delete, bool is_lru_map,
				   bool is_percpu)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	u32 bucket_cnt, total, key_size, value_size, roundup_key_size;
	void *keys = NULL, *values = NULL, *value, *dst_key, *dst_val;
	void __user *uvalues = u64_to_user_ptr(attr->batch.values);
	void __user *ukeys = u64_to_user_ptr(attr->batch.keys);
	void __user *ubatch = u64_to_user_ptr(attr->batch.in_batch);
	u32 batch, max_count, size, bucket_size;
	struct htab_elem *node_to_free = NULL;
	u64 elem_map_flags, map_flags;
	struct hlist_nulls_head *head;
	struct hlist_nulls_node *n;
	unsigned long flags = 0;
	bool locked = false;
	struct htab_elem *l;
	struct bucket *b;
	int ret = 0;

	elem_map_flags = attr->batch.elem_flags;
	if ((elem_map_flags & ~BPF_F_LOCK) ||
	    ((elem_map_flags & BPF_F_LOCK) && !map_value_has_spin_lock(map)))
		return -EINVAL;

	map_flags = attr->batch.flags;
	if (map_flags)
		return -EINVAL;

	max_count = attr->batch.count;
	if (!max_count)
		return 0;

	if (put_user(0, &uattr->batch.count))
		return -EFAULT;

	batch = 0;
	if (ubatch && copy_from_user(&batch, ubatch, sizeof(batch)))
		return -EFAULT;

	if (batch >= htab->n_buckets)
		return -ENOENT;

	key_size = htab->map.key_size;
	roundup_key_size = round_up(htab->map.key_size, 8);
	value_size = htab->map.value_size;
	size = round_up(value_size, 8);
	if (is_percpu)
		value_size = size * num_possible_cpus();
	total = 0;
	


	bucket_size = 5;

alloc:
	


	keys = kvmalloc_array(key_size, bucket_size, GFP_USER | __GFP_NOWARN);
	values = kvmalloc_array(value_size, bucket_size, GFP_USER | __GFP_NOWARN);
	if (!keys || !values) {
		ret = -ENOMEM;
		goto after_loop;
	}

again:
	bpf_disable_instrumentation();
	rcu_read_lock();
again_nocopy:
	dst_key = keys;
	dst_val = values;
	b = &htab->buckets[batch];
	head = &b->head;
	 
	if (locked) {
		ret = htab_lock_bucket(htab, b, batch, &flags);
		if (ret)
			goto next_batch;
	}

	bucket_cnt = 0;
	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		bucket_cnt++;

	if (bucket_cnt && !locked) {
		locked = true;
		goto again_nocopy;
	}

	if (bucket_cnt > (max_count - total)) {
		if (total == 0)
			ret = -ENOSPC;
		


		htab_unlock_bucket(htab, b, batch, flags);
		rcu_read_unlock();
		bpf_enable_instrumentation();
		goto after_loop;
	}

	if (bucket_cnt > bucket_size) {
		bucket_size = bucket_cnt;
		


		htab_unlock_bucket(htab, b, batch, flags);
		rcu_read_unlock();
		bpf_enable_instrumentation();
		kvfree(keys);
		kvfree(values);
		goto alloc;
	}

	 
	if (!locked)
		goto next_batch;

	hlist_nulls_for_each_entry_safe(l, n, head, hash_node) {
		memcpy(dst_key, l->key, key_size);

		if (is_percpu) {
			int off = 0, cpu;
			void __percpu *pptr;

			pptr = htab_elem_get_ptr(l, map->key_size);
			for_each_possible_cpu(cpu) {
				bpf_long_memcpy(dst_val + off,
						per_cpu_ptr(pptr, cpu), size);
				off += size;
			}
		} else {
			value = l->key + roundup_key_size;
			if (elem_map_flags & BPF_F_LOCK)
				orbpf_copy_map_value_locked(map, dst_val, value,
						      true);
			else
				orbpf_copy_map_value(map, dst_val, value);
			orbpf_check_and_init_map_lock(map, dst_val);
		}
		if (do_delete) {
			hlist_nulls_del_rcu(&l->hash_node);

			




			if (is_lru_map) {
				l->batch_flink = node_to_free;
				node_to_free = l;
			} else {
				free_htab_elem(htab, l);
			}
		}
		dst_key += key_size;
		dst_val += value_size;
	}

	htab_unlock_bucket(htab, b, batch, flags);
	locked = false;

	while (node_to_free) {
		l = node_to_free;
		node_to_free = node_to_free->batch_flink;
		bpf_lru_push_free(&htab->lru, &l->lru_node);
	}

next_batch:
	


	if (!bucket_cnt && (batch + 1 < htab->n_buckets)) {
		batch++;
		goto again_nocopy;
	}

	rcu_read_unlock();
	bpf_enable_instrumentation();
	if (bucket_cnt && (copy_to_user(ukeys + total * key_size, keys,
	    key_size * bucket_cnt) ||
	    copy_to_user(uvalues + total * value_size, values,
	    value_size * bucket_cnt))) {
		ret = -EFAULT;
		goto after_loop;
	}

	total += bucket_cnt;
	batch++;
	if (batch >= htab->n_buckets) {
		ret = -ENOENT;
		goto after_loop;
	}
	goto again;

after_loop:
	if (ret == -EFAULT)
		goto out;

	 
	ubatch = u64_to_user_ptr(attr->batch.out_batch);
	if (copy_to_user(ubatch, &batch, sizeof(batch)) ||
	    put_user(total, &uattr->batch.count))
		ret = -EFAULT;

out:
	kvfree(keys);
	kvfree(values);
	return ret;
}

static int
htab_percpu_map_lookup_batch(struct bpf_map *map, const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, false,
						  false, true);
}

static int
htab_percpu_map_lookup_and_delete_batch(struct bpf_map *map,
					const union bpf_attr *attr,
					union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, true,
						  false, true);
}

static int
htab_map_lookup_batch(struct bpf_map *map, const union bpf_attr *attr,
		      union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, false,
						  false, false);
}

static int
htab_map_lookup_and_delete_batch(struct bpf_map *map,
				 const union bpf_attr *attr,
				 union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, true,
						  false, false);
}

static int
htab_lru_percpu_map_lookup_batch(struct bpf_map *map,
				 const union bpf_attr *attr,
				 union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, false,
						  true, true);
}

static int
htab_lru_percpu_map_lookup_and_delete_batch(struct bpf_map *map,
					    const union bpf_attr *attr,
					    union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, true,
						  true, true);
}

static int
htab_lru_map_lookup_batch(struct bpf_map *map, const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, false,
						  true, false);
}

static int
htab_lru_map_lookup_and_delete_batch(struct bpf_map *map,
				     const union bpf_attr *attr,
				     union bpf_attr __user *uattr)
{
	return __htab_map_lookup_and_delete_batch(map, attr, uattr, true,
						  true, false);
}
#endif

#if 1
struct bpf_iter_seq_hash_map_info {
	struct bpf_map *map;
	struct bpf_htab *htab;
	void *percpu_value_buf; 
	u32 bucket_id;
	u32 skip_elems;
};

static struct htab_elem *
bpf_hash_map_seq_find_next(struct bpf_iter_seq_hash_map_info *info,
			   struct htab_elem *prev_elem)
{
	const struct bpf_htab *htab = info->htab;
	u32 skip_elems = info->skip_elems;
	u32 bucket_id = info->bucket_id;
	struct hlist_nulls_head *head;
	struct hlist_nulls_node *n;
	struct htab_elem *elem;
	struct bucket *b;
	u32 i, count;

	if (bucket_id >= htab->n_buckets)
		return NULL;

	 
	if (prev_elem) {
		


		n = rcu_dereference_raw(hlist_nulls_next_rcu(&prev_elem->hash_node));
		elem = hlist_nulls_entry_safe(n, struct htab_elem, hash_node);
		if (elem)
			return elem;

		 
		b = &htab->buckets[bucket_id++];
		rcu_read_unlock();
		skip_elems = 0;
	}

	for (i = bucket_id; i < htab->n_buckets; i++) {
		b = &htab->buckets[i];
		rcu_read_lock();

		count = 0;
		head = &b->head;
		hlist_nulls_for_each_entry_rcu(elem, n, head, hash_node) {
			if (count >= skip_elems) {
				info->bucket_id = i;
				info->skip_elems = count;
				return elem;
			}
			count++;
		}

		rcu_read_unlock();
		skip_elems = 0;
	}

	info->bucket_id = i;
	info->skip_elems = 0;
	return NULL;
}

static void *bpf_hash_map_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_hash_map_info *info = seq->private;
	struct htab_elem *elem;

	elem = bpf_hash_map_seq_find_next(info, NULL);
	if (!elem)
		return NULL;

	if (*pos == 0)
		++*pos;
	return elem;
}

static void *bpf_hash_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_hash_map_info *info = seq->private;

	++*pos;
	++info->skip_elems;
	return bpf_hash_map_seq_find_next(info, v);
}

static int __bpf_hash_map_seq_show(struct seq_file *seq, struct htab_elem *elem)
{
	struct bpf_iter_seq_hash_map_info *info = seq->private;
	u32 roundup_key_size, roundup_value_size;
	struct bpf_iter__bpf_map_elem ctx = {};
	struct bpf_map *map = info->map;
	struct bpf_iter_meta meta;
	int ret = 0, off = 0, cpu;
	struct bpf_prog *prog;
	void __percpu *pptr;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, elem == NULL);
	if (prog) {
		ctx.meta = &meta;
		ctx.map = info->map;
		if (elem) {
			roundup_key_size = round_up(map->key_size, 8);
			ctx.key = elem->key;
			if (!info->percpu_value_buf) {
				ctx.value = elem->key + roundup_key_size;
			} else {
				roundup_value_size = round_up(map->value_size, 8);
				pptr = htab_elem_get_ptr(elem, map->key_size);
				for_each_possible_cpu(cpu) {
					bpf_long_memcpy(info->percpu_value_buf + off,
							per_cpu_ptr(pptr, cpu),
							roundup_value_size);
					off += roundup_value_size;
				}
				ctx.value = info->percpu_value_buf;
			}
		}
		ret = bpf_iter_run_prog(prog, &ctx);
	}

	return ret;
}

static int bpf_hash_map_seq_show(struct seq_file *seq, void *v)
{
	return __bpf_hash_map_seq_show(seq, v);
}

static void bpf_hash_map_seq_stop(struct seq_file *seq, void *v)
{
	if (!v)
		(void)__bpf_hash_map_seq_show(seq, NULL);
	else
		rcu_read_unlock();
}

static int bpf_iter_init_hash_map(void *priv_data,
				  struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_hash_map_info *seq_info = priv_data;
	struct bpf_map *map = aux->map;
	void *value_buf;
	u32 buf_size;

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
		buf_size = round_up(map->value_size, 8) * num_possible_cpus();
		value_buf = kmalloc(buf_size, GFP_USER | __GFP_NOWARN);
		if (!value_buf)
			return -ENOMEM;

		seq_info->percpu_value_buf = value_buf;
	}

	seq_info->map = map;
	seq_info->htab = container_of(map, struct bpf_htab, map);
	return 0;
}

static void bpf_iter_fini_hash_map(void *priv_data)
{
	struct bpf_iter_seq_hash_map_info *seq_info = priv_data;

	kfree(seq_info->percpu_value_buf);
}

static const struct seq_operations bpf_hash_map_seq_ops = {
	.start	= bpf_hash_map_seq_start,
	.next	= bpf_hash_map_seq_next,
	.stop	= bpf_hash_map_seq_stop,
	.show	= bpf_hash_map_seq_show,
};

static const struct bpf_iter_seq_info iter_seq_info = {
	.seq_ops		= &bpf_hash_map_seq_ops,
	.init_seq_private	= bpf_iter_init_hash_map,
	.fini_seq_private	= bpf_iter_fini_hash_map,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_hash_map_info),
};

static int bpf_for_each_hash_elem(struct bpf_map *map, void *callback_fn,
				  void *callback_ctx, u64 flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct hlist_nulls_node *n;
	struct htab_elem *elem;
	u32 roundup_key_size;
	int i, num_elems = 0;
	void __percpu *pptr;
	struct bucket *b;
	void *key, *val;
	bool is_percpu;
	u64 ret = 0;

	if (flags != 0)
		return -EINVAL;

	is_percpu = htab_is_percpu(htab);

	roundup_key_size = round_up(map->key_size, 8);
	


	if (is_percpu)
		migrate_disable();
	for (i = 0; i < htab->n_buckets; i++) {
		b = &htab->buckets[i];
		rcu_read_lock();
		head = &b->head;
		hlist_nulls_for_each_entry_rcu(elem, n, head, hash_node) {
			key = elem->key;
			if (is_percpu) {
				 
				pptr = htab_elem_get_ptr(elem, map->key_size);
				val = this_cpu_ptr(pptr);
			} else {
				val = elem->key + roundup_key_size;
			}
			num_elems++;
			ret = BPF_CAST_CALL(callback_fn)((u64)(long)map,
					(u64)(long)key, (u64)(long)val,
					(u64)(long)callback_ctx, 0);
			 
			if (ret) {
				rcu_read_unlock();
				goto out;
			}
		}
		rcu_read_unlock();
	}
out:
	if (is_percpu)
		migrate_enable();
	return num_elems;
}
#endif


const struct bpf_map_ops htab_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = htab_map_alloc_check,
	.map_alloc = htab_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_map_lookup_elem,
	.map_update_elem = htab_map_update_elem,
	.map_delete_elem = htab_map_delete_elem,
	.map_gen_lookup = htab_map_gen_lookup,
	.map_seq_show_elem = htab_map_seq_show_elem,
#if 1
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_hash_elem,
#endif
#if 1
	BATCH_OPS(htab),
#endif




#if 1
	.iter_seq_info = &iter_seq_info,
#endif
};


const struct bpf_map_ops htab_lru_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = htab_map_alloc_check,
	.map_alloc = htab_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_lru_map_lookup_elem,
#if 1
	.map_lookup_elem_sys_only = htab_lru_map_lookup_elem_sys,
#endif
	.map_update_elem = htab_lru_map_update_elem,
	.map_delete_elem = htab_lru_map_delete_elem,
	.map_gen_lookup = htab_lru_map_gen_lookup,
	.map_seq_show_elem = htab_map_seq_show_elem,
#if 1
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_hash_elem,
#endif
#if 1
	BATCH_OPS(htab_lru),
#endif




#if 1
	.iter_seq_info = &iter_seq_info,
#endif
};

 
static void *htab_percpu_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct htab_elem *l = __htab_map_lookup_elem(map, key);

	if (l)
		return this_cpu_ptr(htab_elem_get_ptr(l, map->key_size));
	else
		return NULL;
}

static void *htab_lru_percpu_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct htab_elem *l = __htab_map_lookup_elem(map, key);

	if (l) {
		bpf_lru_node_set_ref(&l->lru_node);
		return this_cpu_ptr(htab_elem_get_ptr(l, map->key_size));
	}

	return NULL;
}

int bpf_percpu_hash_copy(struct bpf_map *map, void *key, void *value)
{
	struct htab_elem *l;
	void __percpu *pptr;
	int ret = -ENOENT;
	int cpu, off = 0;
	u32 size;

	



	size = round_up(map->value_size, 8);
	rcu_read_lock();
	l = __htab_map_lookup_elem(map, key);
	if (!l)
		goto out;
	


	pptr = htab_elem_get_ptr(l, map->key_size);
	for_each_possible_cpu(cpu) {
		bpf_long_memcpy(value + off,
				per_cpu_ptr(pptr, cpu), size);
		off += size;
	}
	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
			   u64 map_flags, bool allsameval)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	int ret;

	rcu_read_lock();
	if (htab_is_lru(htab))
		ret = __htab_lru_percpu_map_update_elem(map, key, value,
							map_flags, true,
							allsameval);
	else
		ret = __htab_percpu_map_update_elem(map, key, value, map_flags,
						    true, allsameval);
	rcu_read_unlock();

	return ret;
}

struct hash_sort_priv {
	int (*cmp_fn)(void *priv, const void *key_a, const void *key_b,
		      const void *val_a, const void *val_b);
	void *user_priv;
	struct bpf_htab *htab;
	unsigned int cpu;
};

static __nocfi int hash_sort_fn(void *priv, list_cmp_arg_t *a, list_cmp_arg_t *b)
{
	struct htab_elem *l_a = list_entry(a, struct htab_sort_node, next)->list;
	struct htab_elem *l_b = list_entry(b, struct htab_sort_node, next)->list;
	struct hash_sort_priv *p = priv;
	struct bpf_htab *htab = p->htab;
	struct bpf_map *map = &htab->map;
	u32 key_size = map->key_size;
	void *val_a, *val_b;

	if (htab_is_percpu(htab)) {
		val_a = per_cpu_ptr(htab_elem_get_ptr(l_a, key_size), p->cpu);
		val_b = per_cpu_ptr(htab_elem_get_ptr(l_b, key_size), p->cpu);
	} else {
		val_a = l_a->key + round_up(key_size, 8);
		val_b = l_b->key + round_up(key_size, 8);
	}

	return p->cmp_fn(p->user_priv, l_a->key, l_b->key, val_a, val_b);
}

int bpf_hash_sort_next_key(struct bpf_map *map, void *key, void *next_key,
			   int (*cmp_fn)(void *priv, const void *key_a,
					 const void *key_b, const void *val_a,
					 const void *val_b), void *priv)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	unsigned int cpu = raw_smp_processor_id();
	struct list_head *s_head = per_cpu_ptr(htab->sort_heads, cpu);
	struct hash_sort_priv sort_data;
	struct htab_elem *l;
	u32 hash;

	 
	if (key) {
		struct htab_sort_node *s;

		l = __htab_map_lookup_elem(map, key);
		if (!l)
			return -EINVAL;

		s = list_next_entry(per_cpu_ptr(l->sort_nodes, cpu), next);
		if (list_entry_is_head(s, s_head, next))
			return -ENOENT;

		memcpy(next_key, s->list->key, map->key_size);
		return 0;
	}

	INIT_LIST_HEAD(s_head);

	 
	for (hash = 0; hash < htab->n_buckets; hash++) {
		struct bucket *b = &htab->buckets[hash];
		struct hlist_nulls_head *head = &b->head;
		struct hlist_nulls_node *n;

		hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
			list_add(&per_cpu_ptr(l->sort_nodes, cpu)->next, s_head);
	}

	if (list_empty(s_head))
		return -ENOENT;

	 
	sort_data = (typeof(sort_data)){
		.cmp_fn = cmp_fn,
		.user_priv = priv,
		.htab = htab,
		.cpu = cpu
	};
	list_sort(&sort_data, s_head,
#ifdef ORBPF_CONF_LIST_CMP_FUNC_T
		  (list_cmp_func_t) hash_sort_fn
#else
		  hash_sort_fn
#endif
		  );

	 
	l = list_first_entry(s_head, struct htab_sort_node, next)->list;
	memcpy(next_key, l->key, map->key_size);
	return 0;
}

static void htab_percpu_map_seq_show_elem(struct bpf_map *map, void *key,
					  struct seq_file *m)
{
	struct htab_elem *l;
	void __percpu *pptr;
	int cpu;

	rcu_read_lock();

	l = __htab_map_lookup_elem(map, key);
	if (!l) {
		rcu_read_unlock();
		return;
	}

	btf_type_seq_show(map->btf, map->btf_key_type_id, key, m);
	seq_puts(m, ": {\n");
	pptr = htab_elem_get_ptr(l, map->key_size);
	for_each_possible_cpu(cpu) {
		seq_printf(m, "\tcpu%d: ", cpu);
		btf_type_seq_show(map->btf, map->btf_value_type_id,
				  per_cpu_ptr(pptr, cpu), m);
		seq_puts(m, "\n");
	}
	seq_puts(m, "}\n");

	rcu_read_unlock();
}


const struct bpf_map_ops htab_percpu_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = htab_map_alloc_check,
	.map_alloc = htab_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_percpu_map_lookup_elem,
	.map_update_elem = htab_percpu_map_update_elem,
	.map_delete_elem = htab_map_delete_elem,
	.map_seq_show_elem = htab_percpu_map_seq_show_elem,
#if 1
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_hash_elem,
#endif
#if 1
	BATCH_OPS(htab_percpu),
#endif




#if 1
	.iter_seq_info = &iter_seq_info,
#endif
};


const struct bpf_map_ops htab_lru_percpu_map_ops = {
#if 1
	.map_meta_equal = bpf_map_meta_equal,
#endif
	.map_alloc_check = htab_map_alloc_check,
	.map_alloc = htab_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_lru_percpu_map_lookup_elem,
	.map_update_elem = htab_lru_percpu_map_update_elem,
	.map_delete_elem = htab_lru_map_delete_elem,
	.map_seq_show_elem = htab_percpu_map_seq_show_elem,
#if 1
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_hash_elem,
#endif
#if 1
	BATCH_OPS(htab_lru_percpu),
#endif




#if 1
	.iter_seq_info = &iter_seq_info,
#endif
};

static int fd_htab_map_alloc_check(union bpf_attr *attr)
{
	if (attr->value_size != sizeof(u32))
		return -EINVAL;
	return htab_map_alloc_check(attr);
}

static void fd_htab_map_free(struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_node *n;
	struct hlist_nulls_head *head;
	struct htab_elem *l;
	int i;

	for (i = 0; i < htab->n_buckets; i++) {
		head = select_bucket(htab, i);

		hlist_nulls_for_each_entry_safe(l, n, head, hash_node) {
			void *ptr = fd_htab_map_get_ptr(map, l);

			map->ops->map_fd_put_ptr(ptr);
		}
	}

	htab_map_free(map);
}

 
int bpf_fd_htab_map_lookup_elem(struct bpf_map *map, void *key, u32 *value)
{
	void **ptr;
	int ret = 0;

	if (!map->ops->map_fd_sys_lookup_elem)
		return -ENOTSUPP;

	rcu_read_lock();
	ptr = htab_map_lookup_elem(map, key);
	if (ptr)
		*value = map->ops->map_fd_sys_lookup_elem(READ_ONCE(*ptr));
	else
		ret = -ENOENT;
	rcu_read_unlock();

	return ret;
}

 
int bpf_fd_htab_map_update_elem(struct bpf_map *map, struct file *map_file,
				void *key, void *value, u64 map_flags)
{
	void *ptr;
	int ret;
	u32 ufd = *(u32 *)value;

	ptr = map->ops->map_fd_get_ptr(map, map_file, ufd);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	ret = htab_map_update_elem(map, key, &ptr, map_flags);
	if (ret)
		map->ops->map_fd_put_ptr(ptr);

	return ret;
}

static struct bpf_map *htab_of_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map, *inner_map_meta;

	inner_map_meta = bpf_map_meta_alloc(attr->inner_map_fd);
	if (IS_ERR(inner_map_meta))
		return inner_map_meta;

	map = htab_map_alloc(attr);
	if (IS_ERR(map)) {
		bpf_map_meta_free(inner_map_meta);
		return map;
	}

	map->inner_map_meta = inner_map_meta;

	return map;
}

static void *htab_of_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map  = htab_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}

static


#if 1
int
#endif
htab_of_map_gen_lookup(struct bpf_map *map,
				  struct bpf_insn *insn_buf)
{
	struct bpf_insn *insn = insn_buf;
	const int ret = BPF_REG_0;

	BUILD_BUG_ON(!__same_type(&__htab_map_lookup_elem,
		     (void *(*)(struct bpf_map *map, void *key))NULL));
	*insn++ = BPF_EMIT_CALL(BPF_CAST_CALL(__htab_map_lookup_elem));
	*insn++ = BPF_JMP_IMM(BPF_JEQ, ret, 0, 2);
	*insn++ = BPF_ALU64_IMM(BPF_ADD, ret,
				offsetof(struct htab_elem, key) +
				round_up(map->key_size, 8));
	*insn++ = BPF_LDX_MEM(BPF_DW, ret, ret, 0);

	return insn - insn_buf;
}

static void htab_of_map_free(struct bpf_map *map)
{
	bpf_map_meta_free(map->inner_map_meta);
	fd_htab_map_free(map);
}


const struct bpf_map_ops htab_of_maps_map_ops = {
	.map_alloc_check = fd_htab_map_alloc_check,
	.map_alloc = htab_of_map_alloc,
	.map_free = htab_of_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_of_map_lookup_elem,
	.map_delete_elem = htab_map_delete_elem,
	.map_fd_get_ptr = bpf_map_fd_get_ptr,
	.map_fd_put_ptr = bpf_map_fd_put_ptr,
	.map_fd_sys_lookup_elem = bpf_map_fd_sys_lookup_elem,
	.map_gen_lookup = htab_of_map_gen_lookup,
	.map_check_btf = map_check_no_btf,




};