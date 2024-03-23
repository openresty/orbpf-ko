/* Copyright (C) by OpenResty Inc. All rights reserved. */
 

 
#ifdef CONFIG_ARM64
SYM(aarch64_insn_gen_add_sub_imm)
SYM(aarch64_insn_gen_add_sub_shifted_reg)
SYM(aarch64_insn_gen_bitfield)
SYM(aarch64_insn_gen_branch_imm)
SYM(aarch64_insn_gen_branch_reg)
SYM(aarch64_insn_gen_comp_branch_imm)
SYM(aarch64_insn_gen_cond_branch_imm)
SYM(aarch64_insn_gen_data1)
SYM(aarch64_insn_gen_data2)
SYM(aarch64_insn_gen_data3)
SYM(aarch64_insn_gen_hint)
SYM(aarch64_insn_gen_load_store_ex)
SYM(aarch64_insn_gen_load_store_pair)
SYM(aarch64_insn_gen_load_store_reg)
SYM(aarch64_insn_gen_logical_immediate)
SYM(aarch64_insn_gen_logical_shifted_reg)
SYM(aarch64_insn_gen_movewide)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
SYM(aarch64_insn_gen_stadd)
#endif
#endif
SYM(find_vm_area)
SYM(free_uid)
SYM(get_callchain_buffers)
#ifdef ORBPF_CONF_NS_MATCH
SYM(ns_match)
#endif
SYM(_parse_integer)
SYM(_parse_integer_fixup_radix)
SYM(perf_event_get)
SYM(perf_event_read_local)
SYM(put_task_stack)
SYM(set_memory_ro)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
SYM(set_memory_rw)
#endif
SYM(set_memory_x)
SYM(sprint_backtrace)
#ifdef ORBPF_CONF_STRNCPY_FROM_USER_NOFAULT
SYM(strncpy_from_user_nofault)
#elif defined(ORBPF_CONF_STRNCPY_FROM_UNSAFE_USER)
SYM(strncpy_from_unsafe_user)
#endif

#ifdef ORBPF_CONF_STRNCPY_FROM_KERNEL_NOFAULT
SYM(strncpy_from_kernel_nofault)
#endif
#ifdef ORBPF_CONF_STRNCPY_FROM_UNSAFE
SYM(strncpy_from_unsafe)
#endif
SYM(__vmalloc_node_range)

























































#if 1
 
SYM(find_ge_pid)
SYM(get_perf_callchain)
SYM(get_task_exe_file)
SYM(group_send_sig_info)
SYM(module_alloc)
SYM(module_memfree)
SYM(perf_event_output)
SYM(__printk_safe_enter)
SYM(__printk_safe_exit)
SYM(put_callchain_buffers)
SYM(task_work_add)
SYM(signal_wake_up_state)
SYM(__lock_task_sighand)
#endif  
#ifndef ORBPF_CONF_NMI_UACCESS_OKAY
SYM(nmi_uaccess_okay)
#endif