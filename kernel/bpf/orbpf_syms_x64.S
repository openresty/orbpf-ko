/* Copyright (C) by OpenResty Inc. All rights reserved. */
 

#include <linux/orbpf_asm_compat.h>
#include <linux/version.h>
#include <linux/orbpf_conf.h>
#include <asm/nospec-branch.h>

#define SYM(sym) .globl orbpf__##sym
#include "orbpf_syms_list.h"
SYM(kallsyms_lookup_name)  
#undef SYM






.macro symdef sym
SYM_CODE_START(\sym)
	movq orbpf__\sym, %r11
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	JMP_NOSPEC %r11
#else
	JMP_NOSPEC r11
#endif
SYM_CODE_END(\sym)
.endm

#define SYM(sym) symdef sym
#include "orbpf_syms_list.h"
SYM(kallsyms_lookup_name)  
#undef SYM