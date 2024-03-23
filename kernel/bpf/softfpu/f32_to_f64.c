/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_TO_F64_C_INCLUDED_
#define _F32_TO_F64_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float64_t f32_to_f64( float32_t a )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    bool sign;
    int_fast16_t exp;
    uint_fast32_t frac;
    struct commonNaN commonNaN;
    uint_fast64_t uiZ;
    struct exp16_sig32 normExpSig;
    union ui64_f64 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    sign = signF32UI( uiA );
    exp  = expF32UI( uiA );
    frac = fracF32UI( uiA );
    

    if ( exp == 0xFF ) {
        if ( frac ) {
            softfloat_f32UIToCommonNaN( uiA, &commonNaN );
            uiZ = softfloat_commonNaNToF64UI( &commonNaN );
        } else {
            uiZ = packToF64UI( sign, 0x7FF, 0 );
        }
        goto uiZ;
    }
    

    if ( ! exp ) {
        if ( ! frac ) {
            uiZ = packToF64UI( sign, 0, 0 );
            goto uiZ;
        }
        normExpSig = softfloat_normSubnormalF32Sig( frac );
        exp = normExpSig.exp - 1;
        frac = normExpSig.sig;
    }
    

    uiZ = packToF64UI( sign, exp + 0x380, (uint_fast64_t) frac<<29 );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   