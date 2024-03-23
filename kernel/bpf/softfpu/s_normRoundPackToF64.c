/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_NORMROUNDPACKTOF64_C_INCLUDED_
#define _S_NORMROUNDPACKTOF64_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"

float64_t
static inline softfloat_normRoundPackToF64( bool sign, int_fast16_t exp, uint_fast64_t sig )
{
    int_fast8_t shiftDist;
    union ui64_f64 uZ;

    shiftDist = softfloat_countLeadingZeros64( sig ) - 1;
    exp -= shiftDist;
    if ( (10 <= shiftDist) && ((unsigned int) exp < 0x7FD) ) {
        uZ.ui = packToF64UI( sign, sig ? exp : 0, sig<<(shiftDist - 10) );
        return uZ.f;
    } else {
        return softfloat_roundPackToF64( sign, exp, sig<<shiftDist );
    }

}

#endif   