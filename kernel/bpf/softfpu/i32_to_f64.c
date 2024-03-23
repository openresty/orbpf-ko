/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _I32_TO_F64_C_INCLUDED_
#define _I32_TO_F64_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float64_t i32_to_f64( int32_t a )
{
    uint_fast64_t uiZ;
    bool sign;
    uint_fast32_t absA;
    int_fast8_t shiftDist;
    union ui64_f64 uZ;

    if ( ! a ) {
        uiZ = 0;
    } else {
        sign = (a < 0);
        absA = sign ? -(uint_fast32_t) a : (uint_fast32_t) a;
        shiftDist = softfloat_countLeadingZeros32( absA ) + 21;
        uiZ =
            packToF64UI(
                sign, 0x432 - shiftDist, (uint_fast64_t) absA<<shiftDist );
    }
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   