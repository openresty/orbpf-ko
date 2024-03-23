/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_TO_F32_C_INCLUDED_
#define _F64_TO_F32_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float32_t f64_to_f32( float64_t a )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool sign;
    int_fast16_t exp;
    uint_fast64_t frac;
    struct commonNaN commonNaN;
    uint_fast32_t uiZ, frac32;
    union ui32_f32 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    sign = signF64UI( uiA );
    exp  = expF64UI( uiA );
    frac = fracF64UI( uiA );
    

    if ( exp == 0x7FF ) {
        if ( frac ) {
            softfloat_f64UIToCommonNaN( uiA, &commonNaN );
            uiZ = softfloat_commonNaNToF32UI( &commonNaN );
        } else {
            uiZ = packToF32UI( sign, 0xFF, 0 );
        }
        goto uiZ;
    }
    

    frac32 = softfloat_shortShiftRightJam64( frac, 22 );
    if ( ! (exp | frac32) ) {
        uiZ = packToF32UI( sign, 0, 0 );
        goto uiZ;
    }
    

    return softfloat_roundPackToF32( sign, exp - 0x381, frac32 | 0x40000000 );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   