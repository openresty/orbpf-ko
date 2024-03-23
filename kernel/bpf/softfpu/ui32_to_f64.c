/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _UI32_TO_F64_C_INCLUDED_
#define _UI32_TO_F64_C_INCLUDED_

#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float64_t ui32_to_f64( uint32_t a )
{
    uint_fast64_t uiZ;
    int_fast8_t shiftDist;
    union ui64_f64 uZ;

    if ( ! a ) {
        uiZ = 0;
    } else {
        shiftDist = softfloat_countLeadingZeros32( a ) + 21;
        uiZ =
            packToF64UI( 0, 0x432 - shiftDist, (uint_fast64_t) a<<shiftDist );
    }
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   