/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"

#ifndef softfloat_mul128To256M

#define softfloat_mul128To256M softfloat_mul128To256M
#include "primitives.h"

void
 softfloat_mul128To256M(
     uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0, uint64_t *zPtr )
{
    struct uint128 p0, p64, p128;
    uint_fast64_t z64, z128, z192;

    p0 = softfloat_mul64To128( a0, b0 );
    zPtr[indexWord( 4, 0 )] = p0.v0;
    p64 = softfloat_mul64To128( a64, b0 );
    z64 = p64.v0 + p0.v64;
    z128 = p64.v64 + (z64 < p64.v0);
    p128 = softfloat_mul64To128( a64, b64 );
    z128 += p128.v0;
    z192 = p128.v64 + (z128 < p128.v0);
    p64 = softfloat_mul64To128( a0, b64 );
    z64 += p64.v0;
    zPtr[indexWord( 4, 1 )] = z64;
    p64.v64 += (z64 < p64.v0);
    z128 += p64.v64;
    zPtr[indexWord( 4, 2 )] = z128;
    zPtr[indexWord( 4, 3 )] = z192 + (z128 < p64.v64);

}

#endif