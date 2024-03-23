/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftLeft128

struct uint128
 softfloat_shortShiftLeft128( uint64_t a64, uint64_t a0, uint_fast8_t dist )
{
    struct uint128 z;

    z.v64 = a64<<dist | a0>>(-dist & 63);
    z.v0 = a0<<dist;
    return z;

}

#endif