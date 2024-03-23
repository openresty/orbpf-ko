/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
#ifndef _ORBPF_ASM_COMPAT_H_
#define _ORBPF_ASM_COMPAT_H_

#include <linux/linkage.h>

#ifndef SYM_CODE_START
#define SYM_CODE_START(sym) ENTRY(sym)
#endif

#ifndef SYM_CODE_END
#define SYM_CODE_END(sym) END(sym)
#endif
#endif  