/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftRightJam128Extra

struct uint128_extra
 softfloat_shortShiftRightJam128Extra(
     uint64_t a64, uint64_t a0, uint64_t extra, uint_fast8_t dist )
{
    uint_fast8_t uNegDist;
    struct uint128_extra z;

    uNegDist = -dist;
    z.v.v64 = a64>>dist;
    z.v.v0 = a64<<(uNegDist & 63) | a0>>dist;
    z.extra = a0<<(uNegDist & 63) | (extra != 0);
    return z;

}

#endif