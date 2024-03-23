/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shiftRightJam64Extra

struct uint64_extra
 softfloat_shiftRightJam64Extra(
     uint64_t a, uint64_t extra, uint_fast32_t dist )
{
    struct uint64_extra z;

    if ( dist < 64 ) {
        z.v = a>>dist;
        z.extra = a<<(-dist & 63);
    } else {
        z.v = 0;
        z.extra = (dist == 64) ? a : (a != 0);
    }
    z.extra |= (extra != 0);
    return z;

}

#endif