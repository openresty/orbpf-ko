/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _PLATFORM_H_INCLUDED_
#define _PLATFORM_H_INCLUDED_



#define LITTLEENDIAN 1



#ifdef __GNUC_STDC_INLINE__
#define INLINE static __attribute__((always_inline)) inline
#else
#define INLINE static __attribute__((always_inline)) inline

#endif



#define SOFTFLOAT_BUILTIN_CLZ 1
 

#endif   