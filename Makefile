# Copyright (C) by OpenResty Inc. All rights reserved.

# inside the kernel build system

OUT := $(M)
ARCH := $(shell uname -m)

ORBPF_KBUILD_CFLAGS := $(call flags,KBUILD_CFLAGS) $(KBUILD_CFLAGS)
ORBPF_CHECK_BUILD := $(CC) -DMODULE $(NOSTDINC_FLAGS) $(KBUILD_CPPFLAGS) $(CPPFLAGS) $(LINUXINCLUDE) $(ORBPF_KBUILD_CFLAGS) $(CFLAGS_KERNEL) $(EXTRA_CFLAGS) $(CFLAGS) -DKBUILD_BASENAME=orbpf -DKBUILD_MODNAME='"orbpf"' -Werror -S -o /dev/null -xc

orbpf-y := \
	kernel/bpf/orbpf.o \
	kernel/bpf/orbpf_syms.o \
	kernel/bpf/orbpf_vsprintf.o \
	kernel/bpf/verifier.o \
	kernel/bpf/helpers.o \
	kernel/bpf/tnum.o \
	kernel/bpf/hashtab.o \
	kernel/bpf/arraymap.o \
	kernel/bpf/percpu_freelist.o \
	kernel/bpf/bpf_lru_list.o \
	kernel/bpf/lpm_trie.o \
	kernel/bpf/queue_stack_maps.o \
	kernel/bpf/ringbuf.o \
	kernel/bpf/disasm.o \
	kernel/bpf/btf.o

ifeq ($(ARCH),x86_64)
orbpf-y += arch/x86/net/bpf_jit_comp.o kernel/bpf/orbpf_syms_x64.o
else
orbpf-y += arch/arm64/net/bpf_jit_comp.o kernel/bpf/orbpf_syms_arm64.o
endif

ifneq ($(CONFIG_ORBPF_NET),)  # is true
N = -DCONFIG_ORBPF_NET=1
orbpf-y += \
	kernel/bpf/orbpf_net.o \
	kernel/bpf/orbpf_net_core.o \
	kernel/bpf/orbpf_net_syscall.o \
	net/core/filter.o
orbpf_net-y := $(orbpf-y)
obj-m := orbpf_net.o
ccflags-y := $(call cc-disable-warning, switch) $(XCFLAGS) -g

ifneq ($(XDP_ADJUST_TAIL_HACK),)
	ccflags-y += -DORBPF_XDP_ADJUST_TAIL_HACK=1
endif

else  # ! CONFIG_ORBPF_NET

orbpf-y += \
	kernel/trace/bpf_trace.o \
	kernel/bpf/orbpf_trace.o \
	kernel/bpf/inode.o \
	kernel/bpf/map_in_map.o \
	kernel/bpf/core.o \
	kernel/bpf/syscall.o \
	kernel/bpf/bpf_iter.o \
	kernel/bpf/map_iter.o \
	kernel/bpf/prog_iter.o
obj-m := orbpf.o
ccflags-y := $(XCFLAGS) -g

endif  # ! CONFIG_ORBPF_NET

ccflags-y += $(N) -I$(OUT)/include -I$(OUT)/kernel/trace -include linux/orbpf.h
asflags-y := $(N) -I$(OUT)/include

$(patsubst %,$(OUT)/%,$(orbpf-y)): $(OUT)/include/linux/orbpf_conf.h

auto_c_files := $(wildcard $(OUT)/auto/*.c)
auto_h_files := $(patsubst %.c,%.h,$(auto_c_files))

uc = $(subst a,A,$(subst b,B,$(subst c,C,$(subst d,D,$(subst e,E,$(subst f,F,$(subst g,G,$(subst h,H,$(subst i,I,$(subst j,J,$(subst k,K,$(subst l,L,$(subst m,M,$(subst n,N,$(subst o,O,$(subst p,P,$(subst q,Q,$(subst r,R,$(subst s,S,$(subst t,T,$(subst u,U,$(subst v,V,$(subst w,W,$(subst x,X,$(subst y,Y,$(subst z,Z,$1))))))))))))))))))))))))))

$(OUT)/include/linux/orbpf_conf.h: $(auto_h_files)
	@echo "  GEN $@"
	$(Q)printf "#ifndef _ORBPF_CONF_H_\n#define _ORBPF_CONF_H_\n\n" > $@
	$(Q)@cat $(sort $^) >> $@
	$(Q)printf "\n#endif  /* _ORBPF_CONF_H_ */\n" >> $@

$(OUT)/auto/%.h: $(OUT)/auto/%.c
	@echo "  GEN $@"
	$(Q)if $(ORBPF_CHECK_BUILD) $< > $<.err 2>&1; then echo "#define ORBPF_CONF_$(subst -,_,$(call uc,$(basename $(notdir $<)))) 1"; fi > $@
