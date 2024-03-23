/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _I64_TO_F32_C_INCLUDED_
#define _I64_TO_F32_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float32_t i64_to_f32( int64_t a )
{
    bool sign;
    uint_fast64_t absA;
    int_fast8_t shiftDist;
    union ui32_f32 u;
    uint_fast32_t sig;

    sign = (a < 0);
    absA = sign ? -(uint_fast64_t) a : (uint_fast64_t) a;
    shiftDist = softfloat_countLeadingZeros64( absA ) - 40;
    if ( 0 <= shiftDist ) {
        u.ui =
            a ? packToF32UI(
                    sign, 0x95 - shiftDist, (uint_fast32_t) absA<<shiftDist )
                : 0;
        return u.f;
    } else {
        shiftDist += 7;
        sig =
            (shiftDist < 0)
                ? softfloat_shortShiftRightJam64( absA, -shiftDist )
                : (uint_fast32_t) absA<<shiftDist;
        return softfloat_roundPackToF32( sign, 0x9C - shiftDist, sig );
    }

}

#endif   