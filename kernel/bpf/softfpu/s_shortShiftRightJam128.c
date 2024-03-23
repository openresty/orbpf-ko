/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftRightJam128

struct uint128
 softfloat_shortShiftRightJam128(
     uint64_t a64, uint64_t a0, uint_fast8_t dist )
{
    uint_fast8_t uNegDist;
    struct uint128 z;

    uNegDist = -dist;
    z.v64 = a64>>dist;
    z.v0 =
        a64<<(uNegDist & 63) | a0>>dist
            | ((uint64_t) (a0<<(uNegDist & 63)) != 0);
    return z;

}

#endif