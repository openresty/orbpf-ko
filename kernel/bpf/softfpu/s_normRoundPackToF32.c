/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_NORMROUNDPACKTOF32_C_INCLUDED_
#define _S_NORMROUNDPACKTOF32_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"

static inline float32_t
 softfloat_normRoundPackToF32( bool sign, int_fast16_t exp, uint_fast32_t sig )
{
    int_fast8_t shiftDist;
    union ui32_f32 uZ;

    shiftDist = softfloat_countLeadingZeros32( sig ) - 1;
    exp -= shiftDist;
    if ( (7 <= shiftDist) && ((unsigned int) exp < 0xFD) ) {
        uZ.ui = packToF32UI( sign, sig ? exp : 0, sig<<(shiftDist - 7) );
        return uZ.f;
    } else {
        return softfloat_roundPackToF32( sign, exp, sig<<shiftDist );
    }

}

#endif   