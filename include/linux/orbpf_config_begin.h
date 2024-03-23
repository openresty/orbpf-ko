/* Copyright (C) by OpenResty Inc. All rights reserved. */
 











#if 1
#ifdef CONFIG_BPF_JIT_ALWAYS_ON
#define ORBPF_OVERRODE_CONFIG_BPF_JIT_ALWAYS_ON
#undef CONFIG_BPF_JIT_ALWAYS_ON
#endif






#include "orbpf_config_begin_raw.h"
#endif  

 
#ifdef CONFIG_DEBUG_INFO_BTF
#define ORBPF_OVERRODE_CONFIG_DEBUG_INFO_BTF
#undef CONFIG_DEBUG_INFO_BTF
#endif

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
#define ORBPF_OVERRODE_CONFIG_DEBUG_INFO_BTF_MODULES
#undef CONFIG_DEBUG_INFO_BTF_MODULES
#endif

#ifdef CONFIG_MEMCG_KMEM
#define ORBPF_OVERRODE_CONFIG_MEMCG_KMEM
#undef CONFIG_MEMCG_KMEM
#endif