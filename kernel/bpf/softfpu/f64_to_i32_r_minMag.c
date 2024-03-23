/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_TO_I32_R_MINMAG_C_INCLUDED_
#define _F64_TO_I32_R_MINMAG_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
int_fast32_t f64_to_i32_r_minMag( float64_t a, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    int_fast16_t exp;
    uint_fast64_t sig;
    int_fast16_t shiftDist;
    bool sign;
    int_fast32_t absZ;

    

    uA.f = a;
    uiA = uA.ui;
    exp = expF64UI( uiA );
    sig = fracF64UI( uiA );
    

    shiftDist = 0x433 - exp;
    if ( 53 <= shiftDist ) {
        if ( exact && (exp | sig) ) {
            softfloat_exceptionFlags |= softfloat_flag_inexact;
        }
        return 0;
    }
    

    sign = signF64UI( uiA );
    if ( shiftDist < 22 ) {
        if (
            sign && (exp == 0x41E) && (sig < UINT64_C( 0x0000000000200000 ))
        ) {
            if ( exact && sig ) {
                softfloat_exceptionFlags |= softfloat_flag_inexact;
            }
            return -0x7FFFFFFF - 1;
        }
        softfloat_raiseFlags( softfloat_flag_invalid );
        return
            (exp == 0x7FF) && sig ? i32_fromNaN
                : sign ? i32_fromNegOverflow : i32_fromPosOverflow;
    }
    

    sig |= UINT64_C( 0x0010000000000000 );
    absZ = sig>>shiftDist;
    if ( exact && ((uint_fast64_t) (uint_fast32_t) absZ<<shiftDist != sig) ) {
        softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return sign ? -absZ : absZ;

}

#endif   