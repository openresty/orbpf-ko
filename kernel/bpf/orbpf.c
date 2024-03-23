/* Copyright (C) by OpenResty Inc. All rights reserved. */
 

#include <linux/miscdevice.h>






















struct {
	int (*const init)(void);
	void (*const exit)(void);
} static const init_exit_funcs[] = {
	{ bpf_pcpu_bpf_user_rnd_state_init0, bpf_pcpu_bpf_user_rnd_state_exit0 }, { bpf_pcpu_pcpu_sd_init_val_init0, bpf_pcpu_pcpu_sd_init_val_exit0 }, { bpf_pcpu_pcpu_agg_histogram_init0, bpf_pcpu_pcpu_agg_histogram_exit0 }, { bpf_pcpu_irqsave_flags_init0, bpf_pcpu_irqsave_flags_exit0 }, { bpf_pcpu_bpf_bprintf_bufs_init0, bpf_pcpu_bpf_bprintf_bufs_exit0 }, { bpf_pcpu_bpf_bprintf_nest_level_init0, bpf_pcpu_bpf_bprintf_nest_level_exit0 }, { bpf_pcpu_orbpf_user_rnd_state_init0, bpf_pcpu_orbpf_user_rnd_state_exit0 }, { bpf_pcpu_pcpu_bpf_programs_init0, bpf_pcpu_pcpu_bpf_programs_exit0 }, { bpf_pcpu_bpf_prog_active_init0, bpf_pcpu_bpf_prog_active_exit0 }, { bpf_pcpu_bpf_trace_sds_init0, bpf_pcpu_bpf_trace_sds_exit0 }, { bpf_pcpu_bpf_trace_nest_level_init0, bpf_pcpu_bpf_trace_nest_level_exit0 }, { bpf_pcpu_send_signal_work_init0, bpf_pcpu_send_signal_work_exit0 }, { bpf_pcpu_pcpu_path_buf_init0, bpf_pcpu_pcpu_path_buf_exit0 }, { bpf_pcpu_mmap_unlock_work_init0, bpf_pcpu_mmap_unlock_work_exit0 },





#if 1
	{ orbpf_trace_init0			 	 },
	{ bpf_jit_charge_init0			 	 },
#ifdef ORBPF_CONF_GROUP_SEND_SIG_INFO
	{ send_signal_irq_work_init4		 	 },
#endif
	{ bpf_init5,				exit_bpf_init5		 },
	{ bpf_map_iter_init7,			exit_bpf_map_iter_init7	 },
#if 0
	{ task_iter_init7,			exit_task_iter_init7	 },
#endif
	{ bpf_prog_iter_init7,			exit_bpf_prog_iter_init7 }
#endif
};

module_param(bpf_jit_enable, int, 0644);

static int orbpf_open(struct inode *inode, struct file *filp)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return 0;
}

static long orbpf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	u8 cmd_type, cmd_nr;
	unsigned int size;

	cmd_type = _IOC_TYPE(cmd);
	cmd_nr = _IOC_NR(cmd);
	size = _IOC_SIZE(cmd);





	if (unlikely(cmd_type != ORBPF_IOC_TYPE))
		return -ENOTTY;

	switch (cmd_nr) {
	case ORBPF_IOC_SYSCALL_NR:
		{
			struct orbpf_syscall syscall;
			struct orbpf_syscall __user *user_sys = (void __user *) arg;
			int err;

			err = orbpf_check_uarg_tail_zero(user_sys, sizeof(syscall), size);
			if (err) {
				return err;
			}
			size = min_t(u32, size, sizeof(syscall));

			memset(&syscall, 0, sizeof(syscall));
			if (copy_from_user(&syscall, user_sys, size))
				return -EFAULT;

			return bpf_syscall(syscall.cmd,
					   u64_to_user_ptr(syscall.uattr),
					   syscall.uattr_size,
					   u64_to_user_ptr(syscall.prog_label),
					   syscall.prog_label_len);
		}
	default:


#if 1
		return orbpf_trace_ioctl(filp, cmd_nr, size, (void __user *)arg);
#endif
	}
}

static const struct file_operations orbpf_fops = {
	.owner = THIS_MODULE,
	.open = orbpf_open,
	.unlocked_ioctl = orbpf_ioctl
};

static struct miscdevice orbpf_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KBUILD_MODNAME,
	.fops = &orbpf_fops
};

static int __init orbpf_init(void)
{
	int i, ret;

	ret = orbpf_load_syms();
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(init_exit_funcs); i++) {
		ret = init_exit_funcs[i].init();
		if (ret) {
			pr_err("%ps failed, ret: %d\n",
			       init_exit_funcs[i].init, ret);
			goto init_func_cleanup;
		}
	}

	ret = misc_register(&orbpf_dev);
	if (ret) {
		pr_err("failed to register misc device, ret: %d\n", ret);
		goto init_func_cleanup;
	}

#if !defined(CONFIG_ORBPF_NET) && defined(ORBPF_CONF_MMAP_READ_TRYLOCK)
	orbpf_vma_helpers_init();
#endif



#if 1
	pr_info("OpenResty eBPF+ loaded.\n");
#endif
	return 0;

init_func_cleanup:
	while (i--) {
		if (init_exit_funcs[i].exit)
			init_exit_funcs[i].exit();
	}
	return ret;
}

static void __exit orbpf_exit(void)
{
	int i;

	misc_deregister(&orbpf_dev);

	for (i = ARRAY_SIZE(init_exit_funcs) - 1; i >= 0; i--) {
		if (init_exit_funcs[i].exit)
			init_exit_funcs[i].exit();
	}
}
module_init(orbpf_init);
module_exit(orbpf_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(ORBPF_KO_VER);