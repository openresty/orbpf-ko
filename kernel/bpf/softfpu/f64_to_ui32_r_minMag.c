/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_TO_UI32_R_MINMAG_C_INCLUDED_
#define _F64_TO_UI32_R_MINMAG_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
uint_fast32_t f64_to_ui32_r_minMag( float64_t a, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    int_fast16_t exp;
    uint_fast64_t sig;
    int_fast16_t shiftDist;
    bool sign;
    uint_fast32_t z;

    

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
    if ( sign || (shiftDist < 21) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return
            (exp == 0x7FF) && sig ? ui32_fromNaN
                : sign ? ui32_fromNegOverflow : ui32_fromPosOverflow;
    }
    

    sig |= UINT64_C( 0x0010000000000000 );
    z = sig>>shiftDist;
    if ( exact && ((uint_fast64_t) z<<shiftDist != sig) ) {
        softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return z;

}

#endif   