/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_TO_UI64_R_MINMAG_C_INCLUDED_
#define _F32_TO_UI64_R_MINMAG_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
uint_fast64_t f32_to_ui64_r_minMag( float32_t a, bool exact )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    int_fast16_t exp;
    uint_fast32_t sig;
    int_fast16_t shiftDist;
    bool sign;
    uint_fast64_t sig64, z;

    

    uA.f = a;
    uiA = uA.ui;
    exp = expF32UI( uiA );
    sig = fracF32UI( uiA );
    

    shiftDist = 0xBE - exp;
    if ( 64 <= shiftDist ) {
        if ( exact && (exp | sig) ) {
            softfloat_exceptionFlags |= softfloat_flag_inexact;
        }
        return 0;
    }
    

    sign = signF32UI( uiA );
    if ( sign || (shiftDist < 0) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return
            (exp == 0xFF) && sig ? ui64_fromNaN
                : sign ? ui64_fromNegOverflow : ui64_fromPosOverflow;
    }
    

    sig |= 0x00800000;
    sig64 = (uint_fast64_t) sig<<40;
    z = sig64>>shiftDist;
    shiftDist = 40 - shiftDist;
    if ( exact && (shiftDist < 0) && (uint32_t) (sig<<(shiftDist & 31)) ) {
        softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return z;

}

#endif   