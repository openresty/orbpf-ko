/* Copyright (C) by OpenResty Inc. All rights reserved. */
 

#include <linux/kprobes.h>
#include <linux/orbpf_conf.h>
#include <linux/sched.h>

int sysctl_perf_event_max_stack = 127  ;






#define SYM(sym) \
static noinline void orbpf_bug__##sym(void)	\
{						\
	BUG();					\
}						\
void *orbpf__##sym = (void *)orbpf_bug__##sym;
#include "orbpf_syms_list.h"
SYM(kallsyms_lookup_name)  
#undef SYM

 
#define SYM(sym) void *orbpf__##sym;
#include "orbpf_objs_list.h"
#undef SYM

static int dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

int orbpf_load_syms(void)
{
	struct kprobe kallsyms_probe = {
		.symbol_name = "kallsyms_lookup_name",
		.pre_handler = dummy_kprobe_handler
	};
	int ret;

	




	ret = register_kprobe(&kallsyms_probe);
	if (ret) {
		pr_err("failed to register kallsyms kprobe, ret: %d\n", ret);
		return ret;
	}

	orbpf__kallsyms_lookup_name = kallsyms_probe.addr;
	unregister_kprobe(&kallsyms_probe);

	cond_resched();

	












#define SYM(sym) \
	orbpf__##sym = (void *)kallsyms_lookup_name(#sym);			\
	if (!orbpf__##sym) {							\
		pr_err("failed to find \"%s\" in kallsyms\n", #sym);		\
		ret = -EOPNOTSUPP;						\
	}									\
	cond_resched();

#include "orbpf_syms_list.h"
#include "orbpf_objs_list.h"

#undef SYM

	return ret;
}

int __weak bpf_pcpu_bpf_user_rnd_state_init0(void) { return 0; } int __weak bpf_pcpu_pcpu_sd_init_val_init0(void) { return 0; } int __weak bpf_pcpu_pcpu_agg_histogram_init0(void) { return 0; } int __weak bpf_pcpu_irqsave_flags_init0(void) { return 0; } int __weak bpf_pcpu_bpf_bprintf_bufs_init0(void) { return 0; } int __weak bpf_pcpu_bpf_bprintf_nest_level_init0(void) { return 0; } int __weak bpf_pcpu_orbpf_user_rnd_state_init0(void) { return 0; } int __weak bpf_pcpu_pcpu_bpf_programs_init0(void) { return 0; } int __weak bpf_pcpu_bpf_prog_active_init0(void) { return 0; } int __weak bpf_pcpu_bpf_trace_sds_init0(void) { return 0; } int __weak bpf_pcpu_bpf_trace_nest_level_init0(void) { return 0; } int __weak bpf_pcpu_send_signal_work_init0(void) { return 0; } int __weak bpf_pcpu_pcpu_path_buf_init0(void) { return 0; } int __weak bpf_pcpu_mmap_unlock_work_init0(void) { return 0; }
void __weak bpf_pcpu_bpf_user_rnd_state_exit0(void) { } void __weak bpf_pcpu_pcpu_sd_init_val_exit0(void) { } void __weak bpf_pcpu_pcpu_agg_histogram_exit0(void) { } void __weak bpf_pcpu_irqsave_flags_exit0(void) { } void __weak bpf_pcpu_bpf_bprintf_bufs_exit0(void) { } void __weak bpf_pcpu_bpf_bprintf_nest_level_exit0(void) { } void __weak bpf_pcpu_orbpf_user_rnd_state_exit0(void) { } void __weak bpf_pcpu_pcpu_bpf_programs_exit0(void) { } void __weak bpf_pcpu_bpf_prog_active_exit0(void) { } void __weak bpf_pcpu_bpf_trace_sds_exit0(void) { } void __weak bpf_pcpu_bpf_trace_nest_level_exit0(void) { } void __weak bpf_pcpu_send_signal_work_exit0(void) { } void __weak bpf_pcpu_pcpu_path_buf_exit0(void) { } void __weak bpf_pcpu_mmap_unlock_work_exit0(void) { }