/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_TO_I32_R_MINMAG_C_INCLUDED_
#define _F32_TO_I32_R_MINMAG_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
int_fast32_t f32_to_i32_r_minMag( float32_t a, bool exact )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    int_fast16_t exp;
    uint_fast32_t sig;
    int_fast16_t shiftDist;
    bool sign;
    int_fast32_t absZ;

    

    uA.f = a;
    uiA = uA.ui;
    exp = expF32UI( uiA );
    sig = fracF32UI( uiA );
    

    shiftDist = 0x9E - exp;
    if ( 32 <= shiftDist ) {
        if ( exact && (exp | sig) ) {
            softfloat_exceptionFlags |= softfloat_flag_inexact;
        }
        return 0;
    }
    

    sign = signF32UI( uiA );
    if ( shiftDist <= 0 ) {
        if ( uiA == packToF32UI( 1, 0x9E, 0 ) ) return -0x7FFFFFFF - 1;
        softfloat_raiseFlags( softfloat_flag_invalid );
        return
            (exp == 0xFF) && sig ? i32_fromNaN
                : sign ? i32_fromNegOverflow : i32_fromPosOverflow;
    }
    

    sig = (sig | 0x00800000)<<8;
    absZ = sig>>shiftDist;
    if ( exact && ((uint_fast32_t) absZ<<shiftDist != sig) ) {
        softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return sign ? -absZ : absZ;

}

#endif   