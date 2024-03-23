/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_mul64ByShifted32To128

struct uint128 softfloat_mul64ByShifted32To128( uint64_t a, uint32_t b )
{
    uint_fast64_t mid;
    struct uint128 z;

    mid = (uint_fast64_t) (uint32_t) a * b;
    z.v0 = mid<<32;
    z.v64 = (uint_fast64_t) (uint32_t) (a>>32) * b + (mid>>32);
    return z;

}

#endif