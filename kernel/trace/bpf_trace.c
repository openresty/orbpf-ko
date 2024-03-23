/* Copyright (C) by OpenResty Inc. All rights reserved. */



#include "../bpf/mmap_unlock_work.h"
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/bpf_perf_event.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/btf_ids.h>
#include <linux/bpf_lsm.h>
#include <linux/fs_struct.h>



#include <uapi/linux/bpf.h>
#include <uapi/linux/btf.h>

#define CREATE_TRACE_POINTS
#include "bpf_trace.h"
#include <linux/orbpf_config_begin.h>  

#define bpf_event_rcu_dereference(p)					\
	rcu_dereference_protected(p, lockdep_is_held(&bpf_event_mutex))

static struct bpf_trace_sample_data __percpu *bpf_trace_sds; static int __percpu *bpf_trace_nest_level; static struct send_signal_irq_work __percpu *send_signal_work; static char  __percpu *pcpu_path_buf; struct mmap_unlock_irq_work __percpu *mmap_unlock_work;













































static int bpf_btf_printf_prepare(struct btf_ptr *ptr, u32 btf_ptr_size,
				  u64 flags, const struct btf **btf,
				  s32 *btf_id);

























































#ifdef CONFIG_BPF_KPROBE_OVERRIDE
BPF_CALL_2(bpf_override_return, struct pt_regs *, regs, unsigned long, rc)
{
	regs_set_return_value(regs, rc);
	override_function_with_return(regs);
	return 0;
}

static const struct bpf_func_proto bpf_override_return_proto = {
	.func		= bpf_override_return,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
#endif

static __always_inline int
bpf_probe_read_user_common(void *dst, u32 size, const void __user *unsafe_ptr)
{
	int ret;

	ret = orbpf_copy_from_user_nofault(dst, unsafe_ptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);
	return ret;
}

BPF_CALL_3(bpf_probe_read_user, void *, dst, u32, size,
	   const void __user *, unsafe_ptr)
{
	return bpf_probe_read_user_common(dst, size, unsafe_ptr);
}

const struct bpf_func_proto bpf_probe_read_user_proto = {
	.func		= bpf_probe_read_user,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

static __always_inline int
bpf_probe_read_user_str_common(void *dst, u32 size,
			       const void __user *unsafe_ptr)
{
	int ret;

	









	ret = orbpf_strncpy_from_user_nofault(dst, unsafe_ptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);
	return ret;
}

BPF_CALL_3(bpf_probe_read_user_str, void *, dst, u32, size,
	   const void __user *, unsafe_ptr)
{
	return bpf_probe_read_user_str_common(dst, size, unsafe_ptr);
}

const struct bpf_func_proto bpf_probe_read_user_str_proto = {
	.func		= bpf_probe_read_user_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

static __always_inline int
bpf_probe_read_kernel_common(void *dst, u32 size, const void *unsafe_ptr)
{
	int ret;

	ret = copy_from_kernel_nofault(dst, unsafe_ptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);
	return ret;
}

BPF_CALL_3(bpf_probe_read_kernel, void *, dst, u32, size,
	   const void *, unsafe_ptr)
{
	return bpf_probe_read_kernel_common(dst, size, unsafe_ptr);
}

const struct bpf_func_proto bpf_probe_read_kernel_proto = {
	.func		= bpf_probe_read_kernel,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

static __always_inline int
bpf_probe_read_kernel_str_common(void *dst, u32 size, const void *unsafe_ptr)
{
	int ret;

	








	ret = strncpy_from_kernel_nofault(dst, unsafe_ptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);
	return ret;
}

BPF_CALL_3(bpf_probe_read_kernel_str, void *, dst, u32, size,
	   const void *, unsafe_ptr)
{
	return bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr);
}

const struct bpf_func_proto bpf_probe_read_kernel_str_proto = {
	.func		= bpf_probe_read_kernel_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

#ifdef CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
BPF_CALL_3(bpf_probe_read_compat, void *, dst, u32, size,
	   const void *, unsafe_ptr)
{
	if ((unsigned long)unsafe_ptr < TASK_SIZE) {
		return bpf_probe_read_user_common(dst, size,
				(__force void __user *)unsafe_ptr);
	}
	return bpf_probe_read_kernel_common(dst, size, unsafe_ptr);
}

static const struct bpf_func_proto bpf_probe_read_compat_proto = {
	.func		= bpf_probe_read_compat,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_probe_read_compat_str, void *, dst, u32, size,
	   const void *, unsafe_ptr)
{
	if ((unsigned long)unsafe_ptr < TASK_SIZE) {
		return bpf_probe_read_user_str_common(dst, size,
				(__force void __user *)unsafe_ptr);
	}
	return bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr);
}

static const struct bpf_func_proto bpf_probe_read_compat_str_proto = {
	.func		= bpf_probe_read_compat_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};
#endif  

BPF_CALL_3(bpf_probe_write_user, void __user *, unsafe_ptr, const void *, src,
	   u32, size)
{
























	return -ENOTSUPP;
}

static const struct bpf_func_proto bpf_probe_write_user_proto = {
	.func		= bpf_probe_write_user,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};

static const struct bpf_func_proto *bpf_get_probe_write_proto(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return NULL;

	pr_warn_ratelimited("%s[%d] is installing a program with bpf_probe_write_user helper that may corrupt user memory!",
			    current->comm, task_pid_nr(current));

	return &bpf_probe_write_user_proto;
}

static DEFINE_RAW_SPINLOCK(trace_printk_lock);

#define MAX_TRACE_PRINTK_VARARGS	3
#define BPF_TRACE_PRINTK_SIZE		1024

BPF_CALL_5(bpf_trace_printk, char *, fmt, u32, fmt_size, u64, arg1,
	   u64, arg2, u64, arg3)
{
	u64 args[MAX_TRACE_PRINTK_VARARGS] = { arg1, arg2, arg3 };
	u32 *bin_args;
	static char buf[BPF_TRACE_PRINTK_SIZE];
	unsigned long flags;
	int ret;

	ret = bpf_bprintf_prepare(fmt, fmt_size, args, &bin_args,
				  MAX_TRACE_PRINTK_VARARGS);
	if (ret < 0)
		return ret;

	raw_spin_lock_irqsave(&trace_printk_lock, flags);
	ret = bstr_printf(buf, sizeof(buf), fmt, bin_args);

	trace_orbpf_trace_printk(buf);
	raw_spin_unlock_irqrestore(&trace_printk_lock, flags);

	bpf_bprintf_cleanup();

	return ret;
}

static const struct bpf_func_proto bpf_trace_printk_proto = {
	.func		= bpf_trace_printk,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

const struct bpf_func_proto *bpf_get_trace_printk_proto(void)
{
	







	if (trace_set_clr_event("bpf_trace", "orbpf_trace_printk", 1))
		pr_warn_ratelimited("could not enable bpf_trace_printk events");

	return &bpf_trace_printk_proto;
}

#define MAX_SEQ_PRINTF_VARARGS		12

BPF_CALL_5(bpf_seq_printf, struct seq_file *, m, char *, fmt, u32, fmt_size,
	   const void *, data, u32, data_len)
{
	int err, num_args;
	u32 *bin_args;

	if (data_len & 7 || data_len > MAX_SEQ_PRINTF_VARARGS * 8 ||
	    (data_len && !data))
		return -EINVAL;
	num_args = data_len / 8;

	err = bpf_bprintf_prepare(fmt, fmt_size, data, &bin_args, num_args);
	if (err < 0)
		return err;

	seq_bprintf(m, fmt, bin_args);

	bpf_bprintf_cleanup();

	return seq_has_overflowed(m) ? -EOVERFLOW : 0;
}

BTF_ID_LIST_SINGLE(btf_seq_file_ids, struct, seq_file)

static const struct bpf_func_proto bpf_seq_printf_proto = {
	.func		= bpf_seq_printf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_seq_file_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type      = ARG_PTR_TO_MEM_OR_NULL,
	.arg5_type      = ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_3(bpf_seq_write, struct seq_file *, m, const void *, data, u32, len)
{
	return seq_write(m, data, len) ? -EOVERFLOW : 0;
}

static const struct bpf_func_proto bpf_seq_write_proto = {
	.func		= bpf_seq_write,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_seq_file_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_4(bpf_seq_printf_btf, struct seq_file *, m, struct btf_ptr *, ptr,
	   u32, btf_ptr_size, u64, flags)
{
	const struct btf *btf;
	s32 btf_id;
	int ret;

	ret = bpf_btf_printf_prepare(ptr, btf_ptr_size, flags, &btf, &btf_id);
	if (ret)
		return ret;

	return btf_type_seq_show_flags(btf, btf_id, ptr->ptr, m, flags);
}

static const struct bpf_func_proto bpf_seq_printf_btf_proto = {
	.func		= bpf_seq_printf_btf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_seq_file_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

static __always_inline int
get_map_perf_counter(struct bpf_map *map, u64 flags,
		     u64 *value, u64 *enabled, u64 *running)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	unsigned int cpu = smp_processor_id();
	u64 index = flags & BPF_F_INDEX_MASK;
	struct bpf_event_entry *ee;

	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;
	if (index == BPF_F_CURRENT_CPU)
		index = cpu;
	if (unlikely(index >= array->map.max_entries))
		return -E2BIG;

	ee = READ_ONCE(array->ptrs[index]);
	if (!ee)
		return -ENOENT;

	return perf_event_read_local(ee->event, value, enabled, running);
}

BPF_CALL_2(bpf_perf_event_read, struct bpf_map *, map, u64, flags)
{
	u64 value = 0;
	int err;

	err = get_map_perf_counter(map, flags, &value, NULL, NULL);
	



	if (err)
		return err;
	return value;
}

static const struct bpf_func_proto bpf_perf_event_read_proto = {
	.func		= bpf_perf_event_read,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_perf_event_read_value, struct bpf_map *, map, u64, flags,
	   struct bpf_perf_event_value *, buf, u32, size)
{
	int err = -EINVAL;

	if (unlikely(size != sizeof(struct bpf_perf_event_value)))
		goto clear;
	err = get_map_perf_counter(map, flags, &buf->counter, &buf->enabled,
				   &buf->running);
	if (unlikely(err))
		goto clear;
	return 0;
clear:
	memset(buf, 0, size);
	return err;
}

static const struct bpf_func_proto bpf_perf_event_read_value_proto = {
	.func		= bpf_perf_event_read_value,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

static __always_inline u64
__bpf_perf_event_output(struct pt_regs *regs, struct bpf_map *map,
			u64 flags, struct perf_sample_data *sd)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	unsigned int cpu = smp_processor_id();
	u64 index = flags & BPF_F_INDEX_MASK;
	struct bpf_event_entry *ee;
	struct perf_event *event;

	if (index == BPF_F_CURRENT_CPU)
		index = cpu;
	if (unlikely(index >= array->map.max_entries))
		return -E2BIG;

	ee = READ_ONCE(array->ptrs[index]);
	if (!ee)
		return -ENOENT;

	event = ee->event;
	if (unlikely(event->attr.type != PERF_TYPE_SOFTWARE ||
		     event->attr.config != PERF_COUNT_SW_BPF_OUTPUT))
		return -EINVAL;

	if (unlikely(event->oncpu != cpu))
		return -EOPNOTSUPP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	perf_event_output(event, sd, regs);
	return 0;
#else
	return perf_event_output(event, sd, regs);
#endif
}





struct bpf_trace_sample_data {
	struct perf_sample_data sds[3];
};



BPF_CALL_5(bpf_perf_event_output, struct pt_regs *, regs, struct bpf_map *, map,
	   u64, flags, void *, data, u64, size)
{
	struct bpf_trace_sample_data *sds = this_cpu_ptr(bpf_trace_sds);
	int nest_level = this_cpu_inc_return(*bpf_trace_nest_level);
	struct perf_raw_record raw = {
		.frag = {
			.size = size,
			.data = data,
		},
	};
	struct perf_sample_data *sd;
	int err;

	if (WARN_ON_ONCE(nest_level > ARRAY_SIZE(sds->sds))) {
		err = -EBUSY;
		goto out;
	}

	sd = &sds->sds[nest_level - 1];

	if (unlikely(flags & ~(BPF_F_INDEX_MASK))) {
		err = -EINVAL;
		goto out;
	}

	perf_sample_data_init(sd, 0, 0);
	sd->raw = &raw;

	err = __bpf_perf_event_output(regs, map, flags, sd);

out:
	this_cpu_dec(*bpf_trace_nest_level);
	return err;
}

static const struct bpf_func_proto bpf_perf_event_output_proto = {
	.func		= bpf_perf_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

















































BPF_CALL_0(bpf_get_current_task)
{
	return (long) current;
}

const struct bpf_func_proto bpf_get_current_task_proto = {
	.func		= bpf_get_current_task,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_task_btf)
{
	return (unsigned long) current;
}

BTF_ID_LIST_SINGLE(bpf_get_current_btf_ids, struct, task_struct)

static const struct bpf_func_proto bpf_get_current_task_btf_proto = {
	.func		= bpf_get_current_task_btf,
	.gpl_only	= true,
	.ret_type	= RET_PTR_TO_BTF_ID,
	.ret_btf_id	= &bpf_get_current_btf_ids[0],
};

BPF_CALL_2(bpf_current_task_under_cgroup, struct bpf_map *, map, u32, idx)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct cgroup *cgrp;

	if (unlikely(idx >= array->map.max_entries))
		return -E2BIG;

	cgrp = READ_ONCE(array->ptrs[idx]);
	if (unlikely(!cgrp))
		return -EAGAIN;

	return task_under_cgroup_hierarchy(current, cgrp);
}

static const struct bpf_func_proto bpf_current_task_under_cgroup_proto = {
	.func           = bpf_current_task_under_cgroup,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
};

struct send_signal_irq_work {
	struct irq_work irq_work;
	struct task_struct *task;
	u32 sig;
	enum pid_type type;
};



#ifdef ORBPF_CONF_GROUP_SEND_SIG_INFO
static void do_bpf_send_signal(struct irq_work *entry)
{
	struct send_signal_irq_work *work;

	work = container_of(entry, struct send_signal_irq_work, irq_work);
	group_send_sig_info(work->sig, SEND_SIG_PRIV, work->task, work->type);
}

static int bpf_send_signal_common(u32 sig, enum pid_type type)
{
	struct send_signal_irq_work *work = NULL;

	




	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING)))
		return -EPERM;
	if (unlikely(uaccess_kernel()))
		return -EPERM;
	if (unlikely(!nmi_uaccess_okay()))
		return -EPERM;

	if (irqs_disabled()) {
		


		if (unlikely(!valid_signal(sig)))
			return -EINVAL;

		work = this_cpu_ptr(send_signal_work);
		if (irq_work_is_busy(&work->irq_work))
			return -EBUSY;

		



		work->task = current;
		work->sig = sig;
		work->type = type;
		irq_work_queue(&work->irq_work);
		return 0;
	}

	return group_send_sig_info(sig, SEND_SIG_PRIV, current, type);
}
#endif   

BPF_CALL_1(bpf_send_signal, u32, sig)
{
#ifdef ORBPF_CONF_GROUP_SEND_SIG_INFO
	return bpf_send_signal_common(sig, PIDTYPE_TGID);
#else
	return -ENOTSUPP;
#endif
}

static const struct bpf_func_proto bpf_send_signal_proto = {
	.func		= bpf_send_signal,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_send_signal_thread, u32, sig)
{
#ifdef ORBPF_CONF_GROUP_SEND_SIG_INFO
	return bpf_send_signal_common(sig, PIDTYPE_PID);
#else
	return -ENOTSUPP;
#endif
}

static const struct bpf_func_proto bpf_send_signal_thread_proto = {
	.func		= bpf_send_signal_thread,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_d_path, struct path *, path, char *, buf, u32, sz)
{
	long len;
	char *p;

	if (!sz)
		return 0;

	p = d_path(path, buf, sz);
	if (IS_ERR(p)) {
		len = PTR_ERR(p);
	} else {
		len = buf + sz - p;
		memmove(buf, p, len);
	}

	return len;
}

BTF_SET_START(btf_allowlist_d_path)
#ifdef CONFIG_SECURITY
BTF_ID(func, security_file_permission)
BTF_ID(func, security_inode_getattr)
BTF_ID(func, security_file_open)
#endif
#ifdef CONFIG_SECURITY_PATH
BTF_ID(func, security_path_truncate)
#endif
BTF_ID(func, vfs_truncate)
BTF_ID(func, vfs_fallocate)
BTF_ID(func, dentry_open)
BTF_ID(func, vfs_getattr)
BTF_ID(func, filp_close)
BTF_SET_END(btf_allowlist_d_path)

static bool bpf_d_path_allowed(const struct bpf_prog *prog)
{
	if (prog->type == BPF_PROG_TYPE_TRACING &&
	    prog->expected_attach_type == BPF_TRACE_ITER)
		return true;

	if (prog->type == BPF_PROG_TYPE_LSM)
		return bpf_lsm_is_sleepable_hook(prog->aux->attach_btf_id);

	return btf_id_set_contains(&btf_allowlist_d_path,
				   prog->aux->attach_btf_id);
}

BTF_ID_LIST_SINGLE(bpf_d_path_btf_ids, struct, path)

static const struct bpf_func_proto bpf_d_path_proto = {
	.func		= bpf_d_path,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_d_path_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.allowed	= bpf_d_path_allowed,
};

#define BTF_F_ALL	(BTF_F_COMPACT  | BTF_F_NONAME | \
			 BTF_F_PTR_RAW | BTF_F_ZERO)

static int bpf_btf_printf_prepare(struct btf_ptr *ptr, u32 btf_ptr_size,
				  u64 flags, const struct btf **btf,
				  s32 *btf_id)
{
	const struct btf_type *t;

	if (unlikely(flags & ~(BTF_F_ALL)))
		return -EINVAL;

	if (btf_ptr_size != sizeof(struct btf_ptr))
		return -EINVAL;

	*btf = bpf_get_btf_vmlinux();

	if (IS_ERR_OR_NULL(*btf))
		return IS_ERR(*btf) ? PTR_ERR(*btf) : -EINVAL;

	if (ptr->type_id > 0)
		*btf_id = ptr->type_id;
	else
		return -EINVAL;

	if (*btf_id > 0)
		t = btf_type_by_id(*btf, *btf_id);
	if (*btf_id <= 0 || !t)
		return -ENOENT;

	return 0;
}

BPF_CALL_5(bpf_snprintf_btf, char *, str, u32, str_size, struct btf_ptr *, ptr,
	   u32, btf_ptr_size, u64, flags)
{
	const struct btf *btf;
	s32 btf_id;
	int ret;

	ret = bpf_btf_printf_prepare(ptr, btf_ptr_size, flags, &btf, &btf_id);
	if (ret)
		return ret;

	return btf_type_snprintf_show(btf, btf_id, ptr->ptr, str, str_size,
				      flags);
}

const struct bpf_func_proto bpf_snprintf_btf_proto = {
	.func		= bpf_snprintf_btf,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

 
static char *d_path_safe(const struct path *path, char *buf, int buflen)
{
	struct dentry *dentry, *root_dentry, *vfsmnt_mnt_root;
	struct vfsmount *vfsmnt, *root_vfsmnt;
	struct mount *mnt, *mnt_parent;
	int i, j;

	 
	if (buflen < 3)
		return ERR_PTR(-ENAMETOOLONG);

	if (get_kernel_nofault(dentry, &path->dentry) ||
	    get_kernel_nofault(vfsmnt, &path->mnt) ||
	    get_kernel_nofault(vfsmnt_mnt_root, &vfsmnt->mnt_root) ||
	    get_kernel_nofault(root_dentry, &current->fs->root.dentry) ||
	    get_kernel_nofault(root_vfsmnt, &current->fs->root.mnt))
		return ERR_PTR(-EFAULT);

	mnt = real_mount(vfsmnt);
	buf[--buflen] = '\0';

	



	for (i = PATH_MAX / 2; i > 0; i--) {
		const struct qstr *const name = &dentry->d_name;
		const unsigned int startlen = buflen;
		const unsigned char *dname;
		struct dentry *parent;
		u32 len;
		char c;

		if (dentry == root_dentry && vfsmnt == root_vfsmnt)
			return &buf[buflen];

		if (get_kernel_nofault(parent, &dentry->d_parent))
			return ERR_PTR(-EFAULT);

		if (dentry == vfsmnt_mnt_root || dentry == parent) {
			if (dentry != vfsmnt_mnt_root)
				return &buf[buflen];

			if (get_kernel_nofault(mnt_parent, &mnt->mnt_parent))
				return ERR_PTR(-EFAULT);

			if (mnt == mnt_parent)
				return &buf[buflen];

			if (get_kernel_nofault(dentry, &mnt->mnt_mountpoint))
				return ERR_PTR(-EFAULT);

			mnt = mnt_parent;
			vfsmnt = &mnt->mnt;
			if (get_kernel_nofault(vfsmnt_mnt_root, &vfsmnt->mnt_root))
				return ERR_PTR(-EFAULT);

			continue;
		}

		if (buflen < 2)
			return ERR_PTR(-ENAMETOOLONG);

		if (get_kernel_nofault(dname, &name->name) ||
		    get_kernel_nofault(len, &name->len))
			return ERR_PTR(-EFAULT);

		while (len--) {
			if (get_kernel_nofault(c, dname++))
				return ERR_PTR(-EFAULT);
			if (!c)
				break;
			if (buflen == 1)
				return ERR_PTR(-ENAMETOOLONG);
			buf[--buflen] = c;
		}

		 
		for (j = 0; j < (startlen - buflen) / 2; j++)
			swap(buf[j + buflen], buf[startlen - j - 1]);

		buf[--buflen] = '/';
		dentry = parent;
	}

	 
	return ERR_PTR(-EFAULT);
}



BPF_CALL_5(bpf_vma_rel2abs, const char *, tgt_path, int, is_code,
	   unsigned long, reladdr, unsigned long *, uaddr,
	   bool *, mmap_is_locked)
{
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	struct mmap_unlock_irq_work *work = NULL;
	bool irq_work_busy = false;
	bool newly_locked = false;
#endif
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	char *buf;
	long rc = 0;
	struct task_struct *task = current;

	if (unlikely(task->flags & PF_KTHREAD)) {
		return -ESRCH;
	}

	



	mm = task->mm;
	if (unlikely(!mm))
		return -ESRCH;





#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	if (unlikely(!*mmap_is_locked)) {
		





		irq_work_busy = bpf_mmap_unlock_get_irq_work(&work);

		if (unlikely(irq_work_busy || !mmap_read_trylock(mm))) {




			return -EBUSY;
		}

		if (work != NULL) {
			*mmap_is_locked = true;
		}

		newly_locked = true;
	}
#endif

#ifdef ORBPF_CONF_MM_MMAP_FIELD
	vma = mm->mmap;
#elif defined(ORBPF_CONF_FIND_VMA)

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	vma = find_vma(mm, 0);
#else
#error "neither mm->mmap field nor mmap_read_trylock() found"
#endif

#endif

	if (unlikely(!vma)) {
		rc = -ESRCH;
		goto done;
	}

	buf = this_cpu_ptr(pcpu_path_buf);
	do {
		struct file *file;
		char *vma_path;

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
		file = vma->vm_file;
#else
		if (get_kernel_nofault(file, &vma->vm_file))
			return -EFAULT;
#endif

		if (file) {
			




			vma_path = d_path_safe(&file->f_path, buf, PATH_MAX);
			if (!IS_ERR(vma_path) && !strcmp(tgt_path, vma_path)) {
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
				*uaddr = vma->vm_start;
#else
				if (get_kernel_nofault(*uaddr, &vma->vm_start))
					return -EFAULT;
#endif

				*uaddr += reladdr;
				break;
			}
		}

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK

#ifdef ORBPF_CONF_FIND_VMA
		vma = find_vma(mm, vma->vm_end);
#else
		vma = vma->vm_next;
#endif

#else   
		if (get_kernel_nofault(vma, &vma->vm_next))
			return -EFAULT;
#endif   
	} while (vma);

	if (!vma) {
		rc = -ENOENT;
	}

done:

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	if (newly_locked)
		bpf_mmap_unlock_mm(work, mm);
#endif
	return rc;
}

const struct bpf_func_proto bpf_vma_rel2abs_proto = {
	.func		= bpf_vma_rel2abs,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_vma_abs2rel, char *, libpath, u32, size, unsigned long, absaddr,
	   unsigned long *, reladdr, bool *, mmap_is_locked)
{
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	struct mmap_unlock_irq_work *work = NULL;
	bool irq_work_busy = false;
	bool newly_locked = false;
#endif
	unsigned long file_start = 0, vm_start, vm_end;
	struct file *file, *prev_file = NULL;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	char *vma_path;
	long rc = 0;
	struct task_struct *task = current;

	if (unlikely(task->flags & PF_KTHREAD)) {
		return -ESRCH;
	}

	



	mm = task->mm;
	if (unlikely(!mm))
		return -ESRCH;





#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	if (unlikely(!*mmap_is_locked)) {
		





		irq_work_busy = bpf_mmap_unlock_get_irq_work(&work);

		if (unlikely(irq_work_busy || !mmap_read_trylock(mm))) {




			return -EBUSY;
		}

		if (work != NULL) {
			*mmap_is_locked = true;
		}

		newly_locked = true;
	}
#endif

#ifdef ORBPF_CONF_MM_MMAP_FIELD
	vma = mm->mmap;
#elif defined(ORBPF_CONF_FIND_VMA)

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	vma = find_vma(mm, 0);
#else
#error "neither mm->mmap field nor mmap_read_trylock() found"
#endif

#endif

	if (unlikely(!vma)) {
		rc = -ESRCH;
		goto done;
	}

	do {
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
		file = vma->vm_file;
		vm_start = vma->vm_start;
		vm_end = vma->vm_end;
#else
		if (get_kernel_nofault(file, &vma->vm_file) ||
		    get_kernel_nofault(vm_start, &vma->vm_start) ||
		    get_kernel_nofault(vm_end, &vma->vm_end))
			return -EFAULT;
#endif

		if (file != prev_file) {
			prev_file = file;
			file_start = vm_start;
		}

		if (absaddr >= vm_start && absaddr < vm_end)
			break;

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
		vma = find_vma(mm, vma->vm_end);
#else
		if (get_kernel_nofault(vma, &vma->vm_next))
			return -EFAULT;
#endif
	} while (vma);

	if (unlikely(!vma || !file)) {
		rc = -ENOENT;
		goto done;
	}

	if (libpath) {
		




		vma_path = d_path_safe(&file->f_path, libpath, size);
		if (IS_ERR(vma_path)) {
			rc = PTR_ERR(vma_path);
			goto done;
		}

		





		if (vma_path > libpath)
			memmove(libpath, vma_path, size - (vma_path - libpath));
	}

	*reladdr = absaddr - file_start;

done:

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	if (newly_locked)
		bpf_mmap_unlock_mm(work, mm);
#endif
	return rc;
}

const struct bpf_func_proto bpf_vma_abs2rel_proto = {
	.func		= bpf_vma_abs2rel,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_vma_base_end_addr, const char *, path,
	   unsigned long *, base_addr, unsigned long *, end_addr,
       bool *, mmap_is_locked)
{
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	struct mmap_unlock_irq_work *work = NULL;
	bool irq_work_busy = false;
	bool newly_locked = false;
#endif
	struct vm_area_struct *prev_vma, *vma;
	struct file *target_file = NULL;
	struct mm_struct *mm;
	char *buf;
	long rc;
	struct task_struct *task = current;

	if (unlikely(task->flags & PF_KTHREAD)) {
		return -ESRCH;
	}

	



	mm = task->mm;
	if (unlikely(!mm))
		return -ESRCH;





#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	if (unlikely(!*mmap_is_locked)) {
		





		irq_work_busy = bpf_mmap_unlock_get_irq_work(&work);

		if (unlikely(irq_work_busy || !mmap_read_trylock(mm))) {




			return -EBUSY;
		}

		if (work != NULL) {
			*mmap_is_locked = true;
		}

		newly_locked = true;




	}
#endif

#ifdef ORBPF_CONF_MM_MMAP_FIELD
	vma = mm->mmap;
#elif defined(ORBPF_CONF_FIND_VMA)

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	vma = find_vma(mm, 0);
#else
#error "neither mm->mmap field nor mmap_read_trylock() found"
#endif

#endif

	if (unlikely(!vma)) {
		rc = -ESRCH;
		goto done;
	}

	buf = this_cpu_ptr(pcpu_path_buf);
	do {
		struct file *file;
		char *vma_path;

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
		file = vma->vm_file;
#else
		if (get_kernel_nofault(file, &vma->vm_file))
			return -EFAULT;
#endif

		 
		if (target_file) {
			 
			if (file != target_file)
				break;
			goto next_vma;
		} else if (!file) {
			 
			goto next_vma;
		}

		




		vma_path = d_path_safe(&file->f_path, buf, PATH_MAX);
		if (IS_ERR(vma_path)) {
			rc = PTR_ERR(vma_path);
			goto done;
		}

		if (strcmp(path, vma_path))
			goto next_vma;

		 
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
		*base_addr = vma->vm_start;
#else
		if (get_kernel_nofault(*base_addr, &vma->vm_start))
			return -EFAULT;
#endif

		target_file = file;
next_vma:
		prev_vma = vma;

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK

#ifdef ORBPF_CONF_FIND_VMA
		vma = find_vma(mm, vma->vm_end);
#else
		vma = vma->vm_next;
#endif

#else   
		if (get_kernel_nofault(vma, &vma->vm_next))
			return -EFAULT;
#endif   
	} while (vma);

	 
	if (!target_file) {
		rc = -EFAULT;
		goto done;
	}

	rc = 0;

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	*end_addr = prev_vma->vm_end;
#else
	 
	if (get_kernel_nofault(*end_addr, &prev_vma->vm_end))
		rc = -EFAULT;
#endif

done:

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	if (newly_locked)
		bpf_mmap_unlock_mm(work, mm);
#endif
	return rc;
}

static const struct bpf_func_proto bpf_vma_base_end_addr_proto = {
	.func		= bpf_vma_base_end_addr,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CONST_STR,
	.arg2_type	= ARG_PTR_TO_LONG,
	.arg3_type	= ARG_PTR_TO_LONG,
};

BPF_CALL_0(bpf_lockdep_release_mmap_lock)
{
#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK
	struct task_struct *task = current;

	if (unlikely(task->flags & PF_KTHREAD))
		return 0;

	if (unlikely(task->mm == NULL))
		return 0;

	orbpf_lockdep_release_mmap_lock(task->mm);
#endif
	return 0;
}

static const struct bpf_func_proto bpf_lockdep_release_mmap_lock_proto = {
	.func		= bpf_lockdep_release_mmap_lock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
};

const struct bpf_func_proto *
bpf_tracing_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_strtol:
		return &bpf_strtol_proto;
	case BPF_FUNC_hash_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_percpu_array_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_percpu_hash_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_hash_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_percpu_hash_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_hash_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_hash_map_clear:
		return &bpf_map_clear_proto;
	case BPF_FUNC_hash_map_get_next_key:
		return &bpf_map_get_next_key_proto;
	case BPF_FUNC_percpu_hash_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_percpu_hash_map_clear:
		return &bpf_map_clear_proto;
	case BPF_FUNC_percpu_hash_map_get_next_key:
		return &bpf_map_get_next_key_proto;
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_map_clear:
		return &bpf_map_clear_proto;
	case BPF_FUNC_map_push_elem:
		return &bpf_map_push_elem_proto;
	case BPF_FUNC_map_pop_elem:
		return &bpf_map_pop_elem_proto;
	case BPF_FUNC_map_peek_elem:
		return &bpf_map_peek_elem_proto;
	case BPF_FUNC_map_get_next_key:
		return &bpf_map_get_next_key_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	case BPF_FUNC_ktime_get_coarse_ns:
		return &bpf_ktime_get_coarse_ns_proto;




	case BPF_FUNC_get_real_pid:
		return &bpf_get_real_pid_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_get_current_task_btf:
		return &bpf_get_current_task_btf_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_perf_event_read:
		return &bpf_perf_event_read_proto;
	case BPF_FUNC_current_task_under_cgroup:
		return &bpf_current_task_under_cgroup_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_probe_write_user:
		return security_locked_down(LOCKDOWN_BPF_WRITE_USER) < 0 ?
		       NULL : bpf_get_probe_write_proto();
	case BPF_FUNC_probe_read_user:
		return &bpf_probe_read_user_proto;
	case BPF_FUNC_probe_read_kernel:
		return security_locked_down(LOCKDOWN_BPF_READ) < 0 ?
		       NULL : &bpf_probe_read_kernel_proto;
	case BPF_FUNC_probe_read_user_str:
		return &bpf_probe_read_user_str_proto;
	case BPF_FUNC_probe_read_kernel_str:
		return security_locked_down(LOCKDOWN_BPF_READ) < 0 ?
		       NULL : &bpf_probe_read_kernel_str_proto;
#ifdef CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
	case BPF_FUNC_probe_read:
		return security_locked_down(LOCKDOWN_BPF_READ) < 0 ?
		       NULL : &bpf_probe_read_compat_proto;
	case BPF_FUNC_probe_read_str:
		return security_locked_down(LOCKDOWN_BPF_READ) < 0 ?
		       NULL : &bpf_probe_read_compat_str_proto;
#endif
#ifdef CONFIG_CGROUPS
	case BPF_FUNC_get_current_cgroup_id:
		return &bpf_get_current_cgroup_id_proto;
#endif
	case BPF_FUNC_send_signal:
		return &bpf_send_signal_proto;
	case BPF_FUNC_send_signal_thread:
		return &bpf_send_signal_thread_proto;
	case BPF_FUNC_perf_event_read_value:
		return &bpf_perf_event_read_value_proto;
	case BPF_FUNC_get_ns_current_pid_tgid:
		return &bpf_get_ns_current_pid_tgid_proto;
	case BPF_FUNC_ringbuf_output:
		return &bpf_ringbuf_output_proto;
	case BPF_FUNC_ringbuf_reserve:
		return &bpf_ringbuf_reserve_proto;
	case BPF_FUNC_ringbuf_submit:
		return &bpf_ringbuf_submit_proto;
	case BPF_FUNC_ringbuf_discard:
		return &bpf_ringbuf_discard_proto;
	case BPF_FUNC_ringbuf_query:
		return &bpf_ringbuf_query_proto;
	case BPF_FUNC_jiffies64:
		return &bpf_jiffies64_proto;




	case BPF_FUNC_copy_from_user:
		return prog->aux->sleepable ? &bpf_copy_from_user_proto : NULL;
	case BPF_FUNC_snprintf_btf:
		return &bpf_snprintf_btf_proto;
	case BPF_FUNC_per_cpu_ptr:
		return &bpf_per_cpu_ptr_proto;
	case BPF_FUNC_this_cpu_ptr:
		return &bpf_this_cpu_ptr_proto;






	case BPF_FUNC_for_each_map_elem:
		return &bpf_for_each_map_elem_proto;
	case BPF_FUNC_snprintf:
		return &bpf_snprintf_proto;
	case BPF_FUNC_vma_rel2abs:
		return &bpf_vma_rel2abs_proto;
	case BPF_FUNC_vma_abs2rel:
		return &bpf_vma_abs2rel_proto;
	case BPF_FUNC_vma_base_end_addr:
		return &bpf_vma_base_end_addr_proto;
	case BPF_FUNC_lockdep_release_mmap_lock:
		return &bpf_lockdep_release_mmap_lock_proto;
	case BPF_FUNC_percpu_hash_stat_lookup_elem:
		return &bpf_percpu_hash_stat_lookup_elem_proto;
	case BPF_FUNC_stat_add:
		return &bpf_stat_add_proto;
	case BPF_FUNC_stat_agg:
		return &bpf_stat_agg_proto;
	case BPF_FUNC_stat_hist:
		return &bpf_stat_hist_proto;
	case BPF_FUNC_gettimeofday_ns:
		return &bpf_gettimeofday_ns_proto;
	case BPF_FUNC_getpgid:
		return &bpf_getpgid_proto;
	case BPF_FUNC_get_cycles:
		return &bpf_get_cycles_proto;
	case BPF_FUNC_hash_map_sort:
		return &bpf_hash_map_sort_proto;
	case BPF_FUNC_call_func:
		return &bpf_call_func_proto;
	case BPF_FUNC_i64_to_f64:
		return &bpf_i64_to_f64_proto;
	case BPF_FUNC_u64_to_f64:
		return &bpf_u64_to_f64_proto;
	case BPF_FUNC_i32_to_f64:
		return &bpf_i32_to_f64_proto;
	case BPF_FUNC_u32_to_f64:
		return &bpf_u32_to_f64_proto;
	case BPF_FUNC_f64_to_i32:
		return &bpf_f64_to_i32_proto;
	case BPF_FUNC_f64_to_u32:
		return &bpf_f64_to_u32_proto;
	case BPF_FUNC_f64_to_i64:
		return &bpf_f64_to_i64_proto;
	case BPF_FUNC_f64_to_u64:
		return &bpf_f64_to_u64_proto;
	case BPF_FUNC_f32_to_f64:
		return &bpf_f32_to_f64_proto;
	case BPF_FUNC_f64_to_f32:
		return &bpf_f64_to_f32_proto;
	case BPF_FUNC_f32_to_i32:
		return &bpf_f32_to_i32_proto;
	case BPF_FUNC_f32_to_u32:
		return &bpf_f32_to_u32_proto;
	case BPF_FUNC_f32_to_i64:
		return &bpf_f32_to_i64_proto;
	case BPF_FUNC_f32_to_u64:
		return &bpf_f32_to_u64_proto;
	case BPF_FUNC_i32_to_f32:
		return &bpf_i32_to_f32_proto;
	case BPF_FUNC_u32_to_f32:
		return &bpf_u32_to_f32_proto;
	case BPF_FUNC_i64_to_f32:
		return &bpf_i64_to_f32_proto;
	case BPF_FUNC_u64_to_f32:
		return &bpf_u64_to_f32_proto;
	case BPF_FUNC_f64_add:
		return &bpf_f64_add_proto;
	case BPF_FUNC_f64_sub:
		return &bpf_f64_sub_proto;
	case BPF_FUNC_f64_mul:
		return &bpf_f64_mul_proto;
	case BPF_FUNC_f64_div:
		return &bpf_f64_div_proto;
	case BPF_FUNC_f64_mod:
		return &bpf_f64_mod_proto;
	case BPF_FUNC_f64_rem:
		return &bpf_f64_rem_proto;
	case BPF_FUNC_f64_sqrt:
		return &bpf_f64_sqrt_proto;
	case BPF_FUNC_f64_neg:
		return &bpf_f64_neg_proto;
	case BPF_FUNC_f64_abs:
		return &bpf_f64_abs_proto;
	case BPF_FUNC_f32_add:
		return &bpf_f32_add_proto;
	case BPF_FUNC_f32_sub:
		return &bpf_f32_sub_proto;
	case BPF_FUNC_f32_mul:
		return &bpf_f32_mul_proto;
	case BPF_FUNC_f32_div:
		return &bpf_f32_div_proto;
	case BPF_FUNC_f32_mod:
		return &bpf_f32_mod_proto;
	case BPF_FUNC_f32_rem:
		return &bpf_f32_rem_proto;
	case BPF_FUNC_f32_sqrt:
		return &bpf_f32_sqrt_proto;
	case BPF_FUNC_f32_neg:
		return &bpf_f32_neg_proto;
	case BPF_FUNC_f32_abs:
		return &bpf_f32_abs_proto;
	case BPF_FUNC_f64_lt:
		return &bpf_f64_lt_proto;
	case BPF_FUNC_f64_le:
		return &bpf_f64_le_proto;
	case BPF_FUNC_f64_eq:
		return &bpf_f64_eq_proto;
	case BPF_FUNC_f32_lt:
		return &bpf_f32_lt_proto;
	case BPF_FUNC_f32_le:
		return &bpf_f32_le_proto;
	case BPF_FUNC_f32_eq:
		return &bpf_f32_eq_proto;
	case BPF_FUNC_get_uregs:
		return &bpf_get_uregs_proto;
	case BPF_FUNC_get_tcb:
		return &bpf_get_tcb_proto;
	default:
		return NULL;
	}
}

static const struct bpf_func_proto *
kprobe_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_perf_event_output:
		return &bpf_perf_event_output_proto;






#ifdef CONFIG_BPF_KPROBE_OVERRIDE
	case BPF_FUNC_override_return:
		return &bpf_override_return_proto;
#endif
	default:
		return bpf_tracing_func_proto(func_id, prog);
	}
}

 
static bool kprobe_prog_is_valid_access(int off, int size, enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct pt_regs))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	



	if (off + size > sizeof(struct pt_regs))
		return false;

	return true;
}

const struct bpf_verifier_ops kprobe_verifier_ops = {
	.get_func_proto  = kprobe_prog_func_proto,
	.is_valid_access = kprobe_prog_is_valid_access,
};

const struct bpf_prog_ops kprobe_prog_ops = {
};

BPF_CALL_5(bpf_perf_event_output_tp, void *, tp_buff, struct bpf_map *, map,
	   u64, flags, void *, data, u64, size)
{
	struct pt_regs *regs = *(struct pt_regs **)tp_buff;

	




	return ____bpf_perf_event_output(regs, map, flags, data, size);
}

static const struct bpf_func_proto bpf_perf_event_output_proto_tp = {
	.func		= bpf_perf_event_output_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_3(bpf_get_stackid_tp, void *, tp_buff, struct bpf_map *, map,
	   u64, flags)
{











    return -ENOTSUPP;
}

static const struct bpf_func_proto bpf_get_stackid_proto_tp = {
	.func		= bpf_get_stackid_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_get_stack_tp, void *, tp_buff, void *, buf, u32, size,
	   u64, flags)
{






    return -ENOTSUPP;
}

static const struct bpf_func_proto bpf_get_stack_proto_tp = {
	.func		= bpf_get_stack_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

static const struct bpf_func_proto *
tp_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_perf_event_output:
		return &bpf_perf_event_output_proto_tp;






	default:
		return bpf_tracing_func_proto(func_id, prog);
	}
}

static bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % sizeof(__u64));
	return true;
}

const struct bpf_verifier_ops tracepoint_verifier_ops = {
	.get_func_proto  = tp_prog_func_proto,
	.is_valid_access = tp_prog_is_valid_access,
};

const struct bpf_prog_ops tracepoint_prog_ops = {
};

BPF_CALL_3(bpf_perf_prog_read_value, struct bpf_perf_event_data_kern *, ctx,
	   struct bpf_perf_event_value *, buf, u32, size)
{
	int err = -EINVAL;

	if (unlikely(size != sizeof(struct bpf_perf_event_value)))
		goto clear;
	err = perf_event_read_local(ctx->event, &buf->counter, &buf->enabled,
				    &buf->running);
	if (unlikely(err))
		goto clear;
	return 0;
clear:
	memset(buf, 0, size);
	return err;
}

static const struct bpf_func_proto bpf_perf_prog_read_value_proto = {
         .func           = bpf_perf_prog_read_value,
         .gpl_only       = true,
         .ret_type       = RET_INTEGER,
         .arg1_type      = ARG_PTR_TO_CTX,
         .arg2_type      = ARG_PTR_TO_UNINIT_MEM,
         .arg3_type      = ARG_CONST_SIZE,
};

BPF_CALL_4(bpf_read_branch_records, struct bpf_perf_event_data_kern *, ctx,
	   void *, buf, u32, size, u64, flags)
{
#ifndef CONFIG_X86
	return -ENOENT;
#else
	static const u32 br_entry_size = sizeof(struct perf_branch_entry);
	struct perf_branch_stack *br_stack = ctx->data->br_stack;
	u32 to_copy;

	if (unlikely(flags & ~BPF_F_GET_BRANCH_RECORDS_SIZE))
		return -EINVAL;

	if (unlikely(!br_stack))
		return -EINVAL;

	if (flags & BPF_F_GET_BRANCH_RECORDS_SIZE)
		return br_stack->nr * br_entry_size;

	if (!buf || (size % br_entry_size != 0))
		return -EINVAL;

	to_copy = min_t(u32, br_stack->nr * br_entry_size, size);
	memcpy(buf, br_stack->entries, to_copy);

	return to_copy;
#endif
}

static const struct bpf_func_proto bpf_read_branch_records_proto = {
	.func           = bpf_read_branch_records,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_PTR_TO_MEM_OR_NULL,
	.arg3_type      = ARG_CONST_SIZE_OR_ZERO,
	.arg4_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto *
pe_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_perf_event_output:
		return &bpf_perf_event_output_proto_tp;






	case BPF_FUNC_perf_prog_read_value:
		return &bpf_perf_prog_read_value_proto;
	case BPF_FUNC_read_branch_records:
		return &bpf_read_branch_records_proto;
	default:
		return bpf_tracing_func_proto(func_id, prog);
	}
}



































































































































const struct bpf_func_proto *
tracing_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
#ifdef CONFIG_NET
	case BPF_FUNC_skb_output:
		return &bpf_skb_output_proto;
	case BPF_FUNC_xdp_output:
		return &bpf_xdp_output_proto;
	case BPF_FUNC_skc_to_tcp6_sock:
		return &bpf_skc_to_tcp6_sock_proto;
	case BPF_FUNC_skc_to_tcp_sock:
		return &bpf_skc_to_tcp_sock_proto;
	case BPF_FUNC_skc_to_tcp_timewait_sock:
		return &bpf_skc_to_tcp_timewait_sock_proto;
	case BPF_FUNC_skc_to_tcp_request_sock:
		return &bpf_skc_to_tcp_request_sock_proto;
	case BPF_FUNC_skc_to_udp6_sock:
		return &bpf_skc_to_udp6_sock_proto;
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_tracing_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_tracing_proto;
	case BPF_FUNC_sock_from_file:
		return &bpf_sock_from_file_proto;
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_ptr_cookie_proto;
#endif
	case BPF_FUNC_seq_printf:
		return prog->expected_attach_type == BPF_TRACE_ITER ?
		       &bpf_seq_printf_proto :
		       NULL;
	case BPF_FUNC_seq_write:
		return prog->expected_attach_type == BPF_TRACE_ITER ?
		       &bpf_seq_write_proto :
		       NULL;
	case BPF_FUNC_seq_printf_btf:
		return prog->expected_attach_type == BPF_TRACE_ITER ?
		       &bpf_seq_printf_btf_proto :
		       NULL;
	case BPF_FUNC_d_path:
		return &bpf_d_path_proto;
	default:
		return bpf_tracing_func_proto(func_id, prog);
	}
}

















static bool tracing_prog_is_valid_access(int off, int size,
					 enum bpf_access_type type,
					 const struct bpf_prog *prog,
					 struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	return btf_ctx_access(off, size, type, prog, info);
}

int __weak bpf_prog_test_run_tracing(struct bpf_prog *prog,
				     const union bpf_attr *kattr,
				     union bpf_attr __user *uattr)
{
	return -ENOTSUPP;
}














const struct bpf_verifier_ops tracing_verifier_ops = {
	.get_func_proto  = tracing_prog_func_proto,
	.is_valid_access = tracing_prog_is_valid_access,
};

const struct bpf_prog_ops tracing_prog_ops = {
	.test_run = bpf_prog_test_run_tracing,
};
























static bool pe_prog_is_valid_access(int off, int size, enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	const int size_u64 = sizeof(u64);

	if (off < 0 || off >= sizeof(struct bpf_perf_event_data))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0) {
		if (sizeof(unsigned long) != 4)
			return false;
		if (size != 8)
			return false;
		if (off % size != 4)
			return false;
	}

	switch (off) {
	case bpf_ctx_range(struct bpf_perf_event_data, sample_period):
		bpf_ctx_record_field_size(info, size_u64);
		if (!bpf_ctx_narrow_access_ok(off, size, size_u64))
			return false;
		break;
	case bpf_ctx_range(struct bpf_perf_event_data, addr):
		bpf_ctx_record_field_size(info, size_u64);
		if (!bpf_ctx_narrow_access_ok(off, size, size_u64))
			return false;
		break;
	default:
		if (size != sizeof(long))
			return false;
	}

	return true;
}

static u32 pe_prog_convert_ctx_access(enum bpf_access_type type,
				      const struct bpf_insn *si,
				      struct bpf_insn *insn_buf,
				      struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct bpf_perf_event_data, sample_period):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_perf_event_data_kern,
						       data), si->dst_reg, si->src_reg,
				      offsetof(struct bpf_perf_event_data_kern, data));
		*insn++ = BPF_LDX_MEM(BPF_DW, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct perf_sample_data, period, 8,
						     target_size));
		break;
	case offsetof(struct bpf_perf_event_data, addr):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_perf_event_data_kern,
						       data), si->dst_reg, si->src_reg,
				      offsetof(struct bpf_perf_event_data_kern, data));
		*insn++ = BPF_LDX_MEM(BPF_DW, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct perf_sample_data, addr, 8,
						     target_size));
		break;
	default:
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_perf_event_data_kern,
						       regs), si->dst_reg, si->src_reg,
				      offsetof(struct bpf_perf_event_data_kern, regs));
		*insn++ = BPF_LDX_MEM(BPF_SIZEOF(long), si->dst_reg, si->dst_reg,
				      si->off);
		break;
	}

	return insn - insn_buf;
}

const struct bpf_verifier_ops perf_event_verifier_ops = {
	.get_func_proto		= pe_prog_func_proto,
	.is_valid_access	= pe_prog_is_valid_access,
	.convert_ctx_access	= pe_prog_convert_ctx_access,
};

const struct bpf_prog_ops perf_event_prog_ops = {
};

















































































































































































































































































#ifdef ORBPF_CONF_GROUP_SEND_SIG_INFO
int send_signal_irq_work_init4(void)
{
	int cpu;
	struct send_signal_irq_work *work;

	for_each_possible_cpu(cpu) {
		work = per_cpu_ptr(send_signal_work, cpu);
		init_irq_work(&work->irq_work, do_bpf_send_signal);
	}
	return 0;
}
#endif   

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK



static void do_mmap_read_unlock(struct irq_work *entry)
{
        struct mmap_unlock_irq_work *work;

        if (WARN_ON_ONCE(IS_ENABLED(CONFIG_PREEMPT_RT)))
                return;

        work = container_of(entry, struct mmap_unlock_irq_work, irq_work);



        mmap_read_unlock_non_owner(work->mm);
}

int orbpf_vma_helpers_init(void)
{
	struct mmap_unlock_irq_work *work;
        int cpu;

        for_each_possible_cpu(cpu) {
                work = per_cpu_ptr(mmap_unlock_work, cpu);
                init_irq_work(&work->irq_work, do_mmap_read_unlock);
        }

	return 0;
}

#endif   

























































int bpf_pcpu_bpf_trace_sds_init0(void) { bpf_trace_sds = alloc_percpu(struct bpf_trace_sample_data); if (unlikely(bpf_trace_sds == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_bpf_trace_nest_level_init0(void) { bpf_trace_nest_level = alloc_percpu(int); if (unlikely(bpf_trace_nest_level == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_send_signal_work_init0(void) { send_signal_work = alloc_percpu(struct send_signal_irq_work); if (unlikely(send_signal_work == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_pcpu_path_buf_init0(void) { pcpu_path_buf = (char  *) alloc_percpu(char [PATH_MAX]); if (unlikely(pcpu_path_buf == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_mmap_unlock_work_init0(void) { mmap_unlock_work = alloc_percpu(struct mmap_unlock_irq_work); if (unlikely(mmap_unlock_work == NULL)) { return -ENOMEM; } return 0; }
void bpf_pcpu_bpf_trace_sds_exit0(void) { free_percpu(bpf_trace_sds); } void bpf_pcpu_bpf_trace_nest_level_exit0(void) { free_percpu(bpf_trace_nest_level); } void bpf_pcpu_send_signal_work_exit0(void) { free_percpu(send_signal_work); } void bpf_pcpu_pcpu_path_buf_exit0(void) { free_percpu(pcpu_path_buf); } void bpf_pcpu_mmap_unlock_work_exit0(void) { free_percpu(mmap_unlock_work); }