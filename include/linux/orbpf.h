/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
#ifndef _ORBPF_H_
#define _ORBPF_H_








#define __LINUX_BPF_TRACE_H__
#define _LINUX_BPF_VERIFIER_H
#define _LINUX_TNUM_H
#define _UAPI__LINUX_BPF_COMMON_H__
#define _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_PERF_EVENT_H__
#define _UAPI__LINUX_BTF_H__

















#if 1
#define _BPF_CGROUP_H
#define _BPF_LIRC_H
#define _BPF_LOCAL_STORAGE_H
#define _BPF_CGROUP_DEFS_H
#define _LINUX_BPF_H
#define _LINUX_BPF_LSM_H
#define _LINUX_BTF_H
#define _LINUX_BTF_IDS_H
#define _LINUX_BUILDID_H
#define __LINUX_FILTER_H__
#define __LINUX_SECURITY_H

 
#define __LINUX_NET_SCM_H
struct scm_creds { };
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt








#include <linux/gfp.h>
#undef __GFP_ACCOUNT
#define __GFP_ACCOUNT ((__force gfp_t)0)
#undef GFP_KERNEL_ACCOUNT
#define GFP_KERNEL_ACCOUNT GFP_KERNEL

#include <linux/module.h>
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(sym)
#undef EXPORT_SYMBOL_GPL
#define EXPORT_SYMBOL_GPL(sym)

#include <linux/tracepoint.h>
#undef EXPORT_TRACEPOINT_SYMBOL
#define EXPORT_TRACEPOINT_SYMBOL(name)
#undef EXPORT_TRACEPOINT_SYMBOL_GPL
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)

 
#include <linux/version.h>
#define SYM(sym) extern void *orbpf__##sym;
#include "../../kernel/bpf/orbpf_objs_list.h"
#undef SYM

#include "orbpf_compat.h"
#include "../uapi/linux/bpf_common.h"
#include "../uapi/linux/bpf.h"
#include "../uapi/linux/btf.h"
#include "../uapi/linux/bpf_perf_event.h"









#if 1
#include "security.h"
#include "btf.h"
#include "btf_ids.h"
#include "bpf.h"
#include "bpf-cgroup.h"
#include "bpf_lsm.h"
#include "bpf-netns.h"
#include "filter.h"
#include "bpf_lirc.h"
#include "tnum.h"
#include "bpf_verifier.h"
#include "bpf_local_storage.h"
#include "bpf_trace.h"
#include "buildid.h"
#include "orbpf_trace.h"
#endif

int bpf_syscall(int cmd, union bpf_attr __user *uattr, unsigned int size,
	char __user *prog_label, u32 prog_label_len);
int orbpf_load_syms(void);

int bpf_pcpu_bpf_user_rnd_state_init0(void); int bpf_pcpu_pcpu_sd_init_val_init0(void); int bpf_pcpu_pcpu_agg_histogram_init0(void); int bpf_pcpu_irqsave_flags_init0(void); int bpf_pcpu_bpf_bprintf_bufs_init0(void); int bpf_pcpu_bpf_bprintf_nest_level_init0(void); int bpf_pcpu_orbpf_user_rnd_state_init0(void); int bpf_pcpu_pcpu_bpf_programs_init0(void); int bpf_pcpu_bpf_prog_active_init0(void); int bpf_pcpu_bpf_trace_sds_init0(void); int bpf_pcpu_bpf_trace_nest_level_init0(void); int bpf_pcpu_send_signal_work_init0(void); int bpf_pcpu_pcpu_path_buf_init0(void); int bpf_pcpu_mmap_unlock_work_init0(void);
void bpf_pcpu_bpf_user_rnd_state_exit0(void); void bpf_pcpu_pcpu_sd_init_val_exit0(void); void bpf_pcpu_pcpu_agg_histogram_exit0(void); void bpf_pcpu_irqsave_flags_exit0(void); void bpf_pcpu_bpf_bprintf_bufs_exit0(void); void bpf_pcpu_bpf_bprintf_nest_level_exit0(void); void bpf_pcpu_orbpf_user_rnd_state_exit0(void); void bpf_pcpu_pcpu_bpf_programs_exit0(void); void bpf_pcpu_bpf_prog_active_exit0(void); void bpf_pcpu_bpf_trace_sds_exit0(void); void bpf_pcpu_bpf_trace_nest_level_exit0(void); void bpf_pcpu_send_signal_work_exit0(void); void bpf_pcpu_pcpu_path_buf_exit0(void); void bpf_pcpu_mmap_unlock_work_exit0(void);









#if defined(DDEBUG) && (DDEBUG)
#define dd(...)  \
    { pr_notice("%s:%d: %s: ", __FILE__, __LINE__, __FUNCTION__); \
        pr_cont(__VA_ARGS__); pr_cont("\n"); }
#define dd0(...)  \
    { pr_notice(__VA_ARGS__); \
        pr_cont("\n"); }
#else
#define dd(...)
#define dd0(...)
#endif

#define btf_is_kernel orbpf__btf_is_kernel
static inline bool btf_is_kernel(const struct btf *btf)
{
	return false;
}

#define bpf_trampoline_put orbpf__bpf_trampoline_put
static inline void bpf_trampoline_put(struct bpf_trampoline *tr) { }




#if 1
 
#define bpf_prog_active orbpf__bpf_prog_active
extern int __percpu *bpf_prog_active;
#endif

#define bpf_disable_instrumentation orbpf__bpf_disable_instrumentation
static inline void bpf_disable_instrumentation(void)
{
	migrate_disable();
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		this_cpu_inc(*bpf_prog_active);
	else
		__this_cpu_inc(*bpf_prog_active);
}

#define bpf_enable_instrumentation orpbf__bpf_enable_instrumentation
static inline void bpf_enable_instrumentation(void)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		this_cpu_dec(*bpf_prog_active);
	else
		__this_cpu_dec(*bpf_prog_active);
	migrate_enable();
}

#define bpf_map_kmalloc_node orbpf__bpf_map_kmalloc_node
static inline void *
bpf_map_kmalloc_node(const struct bpf_map *map, size_t size, gfp_t flags,
		     int node)
{
	return kmalloc_node(size, flags, node);
}

#define bpf_map_kzalloc orbpf__bpf_map_kzalloc
static inline void *
bpf_map_kzalloc(const struct bpf_map *map, size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}

#define bpf_map_alloc_percpu orbpf__bpf_map_alloc_percpu
static inline void __percpu *
bpf_map_alloc_percpu(const struct bpf_map *map, size_t size, size_t align,
		     gfp_t flags)
{
	return __alloc_percpu_gfp(size, align, flags);
}

#define bpf_percpu_hash_update orbpf__bpf_percpu_hash_update
int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
			   u64 flags, bool allsameval);

int bpf_hash_sort_next_key(struct bpf_map *map, void *key, void *next_key,
			   int (*cmp_fn)(void *priv, const void *key_a,
					 const void *key_b, const void *val_a,
					 const void *val_b), void *priv);

int htab_map_clear(struct bpf_map *map);
static inline
int (*bpf_map_clear_fn(const struct bpf_map_ops *ops))(struct bpf_map *)
{
	if (ops == &htab_map_ops || ops == &htab_percpu_map_ops)
		return htab_map_clear;

	return NULL;
}

#define bpf_map_is_dev_bound orbpf__bpf_map_is_dev_bound
static inline bool bpf_map_is_dev_bound(struct bpf_map *map)
{


#if 1
	return false;
#endif
}

extern const struct bpf_func_proto bpf_map_clear_proto;
extern const struct bpf_func_proto bpf_map_get_next_key_proto;

extern const struct bpf_func_proto bpf_percpu_hash_stat_lookup_elem_proto;
extern const struct bpf_func_proto bpf_stat_add_proto;
extern const struct bpf_func_proto bpf_stat_agg_proto;
extern const struct bpf_func_proto bpf_stat_hist_proto;
extern const struct bpf_func_proto bpf_gettimeofday_ns_proto;
extern const struct bpf_func_proto bpf_getpgid_proto;
extern const struct bpf_func_proto bpf_get_cycles_proto;
extern const struct bpf_func_proto bpf_hash_map_sort_proto;
extern const struct bpf_func_proto bpf_call_func_proto;
extern const struct bpf_func_proto bpf_i64_to_f64_proto;
extern const struct bpf_func_proto bpf_u64_to_f64_proto;
extern const struct bpf_func_proto bpf_i32_to_f64_proto;
extern const struct bpf_func_proto bpf_u32_to_f64_proto;
extern const struct bpf_func_proto bpf_f64_to_i32_proto;
extern const struct bpf_func_proto bpf_f64_to_u32_proto;
extern const struct bpf_func_proto bpf_f64_to_i64_proto;
extern const struct bpf_func_proto bpf_f64_to_u64_proto;
extern const struct bpf_func_proto bpf_f32_to_f64_proto;
extern const struct bpf_func_proto bpf_f64_to_f32_proto;
extern const struct bpf_func_proto bpf_f32_to_i32_proto;
extern const struct bpf_func_proto bpf_f32_to_u32_proto;
extern const struct bpf_func_proto bpf_f32_to_i64_proto;
extern const struct bpf_func_proto bpf_f32_to_u64_proto;
extern const struct bpf_func_proto bpf_i32_to_f32_proto;
extern const struct bpf_func_proto bpf_u32_to_f32_proto;
extern const struct bpf_func_proto bpf_i64_to_f32_proto;
extern const struct bpf_func_proto bpf_u64_to_f32_proto;
extern const struct bpf_func_proto bpf_f64_add_proto;
extern const struct bpf_func_proto bpf_f64_sub_proto;
extern const struct bpf_func_proto bpf_f64_mul_proto;
extern const struct bpf_func_proto bpf_f64_div_proto;
extern const struct bpf_func_proto bpf_f64_mod_proto;
extern const struct bpf_func_proto bpf_f64_rem_proto;
extern const struct bpf_func_proto bpf_f64_sqrt_proto;
extern const struct bpf_func_proto bpf_f64_neg_proto;
extern const struct bpf_func_proto bpf_f64_abs_proto;
extern const struct bpf_func_proto bpf_f32_add_proto;
extern const struct bpf_func_proto bpf_f32_sub_proto;
extern const struct bpf_func_proto bpf_f32_mul_proto;
extern const struct bpf_func_proto bpf_f32_div_proto;
extern const struct bpf_func_proto bpf_f32_mod_proto;
extern const struct bpf_func_proto bpf_f32_rem_proto;
extern const struct bpf_func_proto bpf_f32_sqrt_proto;
extern const struct bpf_func_proto bpf_f32_neg_proto;
extern const struct bpf_func_proto bpf_f32_abs_proto;
extern const struct bpf_func_proto bpf_f64_lt_proto;
extern const struct bpf_func_proto bpf_f64_le_proto;
extern const struct bpf_func_proto bpf_f64_eq_proto;
extern const struct bpf_func_proto bpf_f32_lt_proto;
extern const struct bpf_func_proto bpf_f32_le_proto;
extern const struct bpf_func_proto bpf_f32_eq_proto;
extern const struct bpf_func_proto bpf_get_uregs_proto;
extern const struct bpf_func_proto bpf_get_tcb_proto;

#if !defined(CONFIG_ORBPF_NET) && defined(ORBPF_CONF_MMAP_READ_TRYLOCK)
int orbpf_vma_helpers_init(void);
#endif

 
#define ORBPF_KO_VER  "0.0.14"

#endif  