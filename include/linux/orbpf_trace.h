/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
#ifndef _ORBPF_TRACE_H_
#define _ORBPF_TRACE_H_

int orbpf_trace_init0(void);
int bpf_jit_charge_init0(void);
int send_signal_irq_work_init4(void);
int stack_map_init4(void);
int bpf_init5(void);
int bpf_map_iter_init7(void);
int task_iter_init7(void);
int bpf_prog_iter_init7(void);

void exit_bpf_init5(void);
void exit_bpf_map_iter_init7(void);
void exit_task_iter_init7(void);
void exit_bpf_prog_iter_init7(void);

long orbpf_trace_ioctl(struct file *filp, unsigned int cmd_nr,
	unsigned int size, void __user *arg);
const char *orbpf_get_running_prog_label(unsigned int *size_ptr);

extern struct bpf_prog * __percpu *pcpu_bpf_programs;

#endif  