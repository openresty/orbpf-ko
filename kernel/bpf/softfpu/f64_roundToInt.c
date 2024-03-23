/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_ROUNDTOINT_C_INCLUDED_
#define _F64_ROUNDTOINT_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float64_t f64_roundToInt( float64_t a, uint_fast8_t roundingMode, bool exact )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    int_fast16_t exp;
    uint_fast64_t uiZ, lastBitMask, roundBitsMask;
    union ui64_f64 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    exp = expF64UI( uiA );
    

    if ( exp <= 0x3FE ) {
        if ( !(uiA & UINT64_C( 0x7FFFFFFFFFFFFFFF )) ) return a;
        if ( exact ) softfloat_exceptionFlags |= softfloat_flag_inexact;
        uiZ = uiA & packToF64UI( 1, 0, 0 );
        switch ( roundingMode ) {
         case softfloat_round_near_even:
            if ( !fracF64UI( uiA ) ) break;
             
            fallthrough;
         case softfloat_round_near_maxMag:
            if ( exp == 0x3FE ) uiZ |= packToF64UI( 0, 0x3FF, 0 );
            break;
         case softfloat_round_min:
            if ( uiZ ) uiZ = packToF64UI( 1, 0x3FF, 0 );
            break;
         case softfloat_round_max:
            if ( !uiZ ) uiZ = packToF64UI( 0, 0x3FF, 0 );
            break;
#ifdef SOFTFLOAT_ROUND_ODD
         case softfloat_round_odd:
            uiZ |= packToF64UI( 0, 0x3FF, 0 );
            break;
#endif
        }
        goto uiZ;
    }
    

    if ( 0x433 <= exp ) {
        if ( (exp == 0x7FF) && fracF64UI( uiA ) ) {
            uiZ = softfloat_propagateNaNF64UI( uiA, 0 );
            goto uiZ;
        }
        return a;
    }
    

    uiZ = uiA;
    lastBitMask = (uint_fast64_t) 1<<(0x433 - exp);
    roundBitsMask = lastBitMask - 1;
    if ( roundingMode == softfloat_round_near_maxMag ) {
        uiZ += lastBitMask>>1;
    } else if ( roundingMode == softfloat_round_near_even ) {
        uiZ += lastBitMask>>1;
        if ( !(uiZ & roundBitsMask) ) uiZ &= ~lastBitMask;
    } else if (
        roundingMode
            == (signF64UI( uiZ ) ? softfloat_round_min : softfloat_round_max)
    ) {
        uiZ += roundBitsMask;
    }
    uiZ &= ~roundBitsMask;
    if ( uiZ != uiA ) {
#ifdef SOFTFLOAT_ROUND_ODD
        if ( roundingMode == softfloat_round_odd ) uiZ |= lastBitMask;
#endif
        if ( exact ) softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   