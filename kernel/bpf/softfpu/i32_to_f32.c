/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _I32_TO_F32_C_INCLUDED_
#define _I32_TO_F32_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float32_t i32_to_f32( int32_t a )
{
    bool sign;
    union ui32_f32 uZ;
    uint_fast32_t absA;

    sign = (a < 0);
    if ( ! (a & 0x7FFFFFFF) ) {
        uZ.ui = sign ? packToF32UI( 1, 0x9E, 0 ) : 0;
        return uZ.f;
    }
    absA = sign ? -(uint_fast32_t) a : (uint_fast32_t) a;
    return softfloat_normRoundPackToF32( sign, 0x9C, absA );

}

#endif   