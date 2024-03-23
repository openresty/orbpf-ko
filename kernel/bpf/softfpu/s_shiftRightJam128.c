/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shiftRightJam128

struct uint128
 softfloat_shiftRightJam128( uint64_t a64, uint64_t a0, uint_fast32_t dist )
{
    uint_fast8_t u8NegDist;
    struct uint128 z;

    if ( dist < 64 ) {
        u8NegDist = -dist;
        z.v64 = a64>>dist;
        z.v0 =
            a64<<(u8NegDist & 63) | a0>>dist
                | ((uint64_t) (a0<<(u8NegDist & 63)) != 0);
    } else {
        z.v64 = 0;
        z.v0 =
            (dist < 127)
                ? a64>>(dist & 63)
                      | (((a64 & (((uint_fast64_t) 1<<(dist & 63)) - 1)) | a0)
                             != 0)
                : ((a64 | a0) != 0);
    }
    return z;

}

#endif