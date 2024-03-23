/* Copyright (C) by OpenResty Inc. All rights reserved. */






#ifndef _ORBPF_UAPI__LINUX_BPF_PERF_EVENT_H__
#define _ORBPF_UAPI__LINUX_BPF_PERF_EVENT_H__

#include <asm/bpf_perf_event.h>

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

#endif  