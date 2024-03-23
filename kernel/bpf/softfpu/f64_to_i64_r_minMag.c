/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_TO_I64_R_MINMAG_C_INCLUDED_
#define _F64_TO_I64_R_MINMAG_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
int_fast64_t f64_to_i64_r_minMag( float64_t a, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool sign;
    int_fast16_t exp;
    uint_fast64_t sig;
    int_fast16_t shiftDist;
    int_fast64_t absZ;

    

    uA.f = a;
    uiA = uA.ui;
    sign = signF64UI( uiA );
    exp  = expF64UI( uiA );
    sig  = fracF64UI( uiA );
    

    shiftDist = 0x433 - exp;
    if ( shiftDist <= 0 ) {
        

        if ( shiftDist < -10 ) {
            if ( uiA == packToF64UI( 1, 0x43E, 0 ) ) {
                return -INT64_C( 0x7FFFFFFFFFFFFFFF ) - 1;
            }
            softfloat_raiseFlags( softfloat_flag_invalid );
            return
                (exp == 0x7FF) && sig ? i64_fromNaN
                    : sign ? i64_fromNegOverflow : i64_fromPosOverflow;
        }
        

        sig |= UINT64_C( 0x0010000000000000 );
        absZ = sig<<-shiftDist;
    } else {
        

        if ( 53 <= shiftDist ) {
            if ( exact && (exp | sig) ) {
                softfloat_exceptionFlags |= softfloat_flag_inexact;
            }
            return 0;
        }
        

        sig |= UINT64_C( 0x0010000000000000 );
        absZ = sig>>shiftDist;
        if ( exact && (absZ<<shiftDist != sig) ) {
            softfloat_exceptionFlags |= softfloat_flag_inexact;
        }
    }
    return sign ? -absZ : absZ;

}

#endif   