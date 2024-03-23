/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftRightJam64Extra

struct uint64_extra
 softfloat_shortShiftRightJam64Extra(
     uint64_t a, uint64_t extra, uint_fast8_t dist )
{
    struct uint64_extra z;

    z.v = a>>dist;
    z.extra = a<<(-dist & 63) | (extra != 0);
    return z;

}

#endif