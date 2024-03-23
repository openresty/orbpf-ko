/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _UI64_TO_F32_C_INCLUDED_
#define _UI64_TO_F32_C_INCLUDED_

#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float32_t ui64_to_f32( uint64_t a )
{
    int_fast8_t shiftDist;
    union ui32_f32 u;
    uint_fast32_t sig;

    shiftDist = softfloat_countLeadingZeros64( a ) - 40;
    if ( 0 <= shiftDist ) {
        u.ui =
            a ? packToF32UI(
                    0, 0x95 - shiftDist, (uint_fast32_t) a<<shiftDist )
                : 0;
        return u.f;
    } else {
        shiftDist += 7;
        sig =
            (shiftDist < 0) ? softfloat_shortShiftRightJam64( a, -shiftDist )
                : (uint_fast32_t) a<<shiftDist;
        return softfloat_roundPackToF32( 0, 0x9C - shiftDist, sig );
    }

}

#endif   