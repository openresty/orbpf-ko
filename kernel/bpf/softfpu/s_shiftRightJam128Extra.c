/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shiftRightJam128Extra

struct uint128_extra
 softfloat_shiftRightJam128Extra(
     uint64_t a64, uint64_t a0, uint64_t extra, uint_fast32_t dist )
{
    uint_fast8_t u8NegDist;
    struct uint128_extra z;

    u8NegDist = -dist;
    if ( dist < 64 ) {
        z.v.v64 = a64>>dist;
        z.v.v0 = a64<<(u8NegDist & 63) | a0>>dist;
        z.extra = a0<<(u8NegDist & 63);
    } else {
        z.v.v64 = 0;
        if ( dist == 64 ) {
            z.v.v0 = a64;
            z.extra = a0;
        } else {
            extra |= a0;
            if ( dist < 128 ) {
                z.v.v0 = a64>>(dist & 63);
                z.extra = a64<<(u8NegDist & 63);
            } else {
                z.v.v0 = 0;
                z.extra = (dist == 128) ? a64 : (a64 != 0);
            }
        }
    }
    z.extra |= (extra != 0);
    return z;

}

#endif