/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef opts_GCC_h
#define opts_GCC_h 1

#ifdef INLINE

#include "primitiveTypes.h"

#ifdef SOFTFLOAT_BUILTIN_CLZ

INLINE uint_fast8_t softfloat_countLeadingZeros16( uint16_t a )
    { return a ? __builtin_clz( a ) - 16 : 16; }
#define softfloat_countLeadingZeros16 softfloat_countLeadingZeros16

INLINE uint_fast8_t softfloat_countLeadingZeros32( uint32_t a )
    { return a ? __builtin_clz( a ) : 32; }
#define softfloat_countLeadingZeros32 softfloat_countLeadingZeros32

uint_fast8_t softfloat_countLeadingZeros64( uint64_t a )
    { return a ? __builtin_clzll( a ) : 64; }
#define softfloat_countLeadingZeros64 softfloat_countLeadingZeros64

#endif

#ifdef SOFTFLOAT_INTRINSIC_INT128

INLINE struct uint128 softfloat_mul64ByShifted32To128( uint64_t a, uint32_t b )
{
    union { unsigned __int128 ui; struct uint128 s; } uZ;
    uZ.ui = (unsigned __int128) a * ((uint_fast64_t) b<<32);
    return uZ.s;
}
#define softfloat_mul64ByShifted32To128 softfloat_mul64ByShifted32To128

INLINE struct uint128 softfloat_mul64To128( uint64_t a, uint64_t b )
{
    union { unsigned __int128 ui; struct uint128 s; } uZ;
    uZ.ui = (unsigned __int128) a * b;
    return uZ.s;
}
#define softfloat_mul64To128 softfloat_mul64To128

INLINE
struct uint128 softfloat_mul128By32( uint64_t a64, uint64_t a0, uint32_t b )
{
    union { unsigned __int128 ui; struct uint128 s; } uZ;
    uZ.ui = ((unsigned __int128) a64<<64 | a0) * b;
    return uZ.s;
}
#define softfloat_mul128By32 softfloat_mul128By32

INLINE
void
 softfloat_mul128To256M(
     uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0, uint64_t *zPtr )
{
    unsigned __int128 z0, mid1, mid, z128;
    z0 = (unsigned __int128) a0 * b0;
    mid1 = (unsigned __int128) a64 * b0;
    mid = mid1 + (unsigned __int128) a0 * b64;
    z128 = (unsigned __int128) a64 * b64;
    z128 += (unsigned __int128) (mid < mid1)<<64 | mid>>64;
    mid <<= 64;
    z0 += mid;
    z128 += (z0 < mid);
    zPtr[indexWord( 4, 0 )] = z0;
    zPtr[indexWord( 4, 1 )] = z0>>64;
    zPtr[indexWord( 4, 2 )] = z128;
    zPtr[indexWord( 4, 3 )] = z128>>64;
}
#define softfloat_mul128To256M softfloat_mul128To256M

#endif

#endif

#endif