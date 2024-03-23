/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftLeft64To96M

void
 softfloat_shortShiftLeft64To96M(
     uint64_t a, uint_fast8_t dist, uint32_t *zPtr )
{

    zPtr[indexWord( 3, 0 )] = (uint32_t) a<<dist;
    a >>= 32 - dist;
    zPtr[indexWord( 3, 2 )] = a>>32;
    zPtr[indexWord( 3, 1 )] = a;

}

#endif