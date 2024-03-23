/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_TO_UI64_C_INCLUDED_
#define _F64_TO_UI64_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
uint_fast64_t f64_to_ui64( float64_t a, uint_fast8_t roundingMode, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool sign;
    int_fast16_t exp;
    uint_fast64_t sig;
    int_fast16_t shiftDist;
#ifdef SOFTFLOAT_FAST_INT64
    struct uint64_extra sigExtra;
#else
    uint32_t extSig[3];
#endif

    

    uA.f = a;
    uiA = uA.ui;
    sign = signF64UI( uiA );
    exp  = expF64UI( uiA );
    sig  = fracF64UI( uiA );
    

    if ( exp ) sig |= UINT64_C( 0x0010000000000000 );
    shiftDist = 0x433 - exp;
#ifdef SOFTFLOAT_FAST_INT64
    if ( shiftDist <= 0 ) {
        if ( shiftDist < -11 ) goto invalid;
        sigExtra.v = sig<<-shiftDist;
        sigExtra.extra = 0;
    } else {
        sigExtra = softfloat_shiftRightJam64Extra( sig, 0, shiftDist );
    }
    return
        softfloat_roundToUI64(
            sign, sigExtra.v, sigExtra.extra, roundingMode, exact );
#else
    extSig[indexWord( 3, 0 )] = 0;
    if ( shiftDist <= 0 ) {
        if ( shiftDist < -11 ) goto invalid;
        sig <<= -shiftDist;
        extSig[indexWord( 3, 2 )] = sig>>32;
        extSig[indexWord( 3, 1 )] = sig;
    } else {
        extSig[indexWord( 3, 2 )] = sig>>32;
        extSig[indexWord( 3, 1 )] = sig;
        softfloat_shiftRightJam96M( extSig, shiftDist, extSig );
    }
    return softfloat_roundMToUI64( sign, extSig, roundingMode, exact );
#endif
    

 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return
        (exp == 0x7FF) && fracF64UI( uiA ) ? ui64_fromNaN
            : sign ? ui64_fromNegOverflow : ui64_fromPosOverflow;

}

#endif   