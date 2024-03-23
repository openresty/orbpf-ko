/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_TO_UI64_R_MINMAG_C_INCLUDED_
#define _F64_TO_UI64_R_MINMAG_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
uint_fast64_t f64_to_ui64_r_minMag( float64_t a, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    int_fast16_t exp;
    uint_fast64_t sig;
    int_fast16_t shiftDist;
    bool sign;
    uint_fast64_t z;

    

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
    if ( sign ) goto invalid;
    if ( shiftDist <= 0 ) {
        if ( shiftDist < -11 ) goto invalid;
        z = (sig | UINT64_C( 0x0010000000000000 ))<<-shiftDist;
    } else {
        sig |= UINT64_C( 0x0010000000000000 );
        z = sig>>shiftDist;
        if ( exact && (uint64_t) (sig<<(-shiftDist & 63)) ) {
            softfloat_exceptionFlags |= softfloat_flag_inexact;
        }
    }
    return z;
    

 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return
        (exp == 0x7FF) && sig ? ui64_fromNaN
            : sign ? ui64_fromNegOverflow : ui64_fromPosOverflow;

}

#endif   