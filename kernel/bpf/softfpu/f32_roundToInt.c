/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_ROUNDTOINT_C_INCLUDED_
#define _F32_ROUNDTOINT_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float32_t f32_roundToInt( float32_t a, uint_fast8_t roundingMode, bool exact )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    int_fast16_t exp;
    uint_fast32_t uiZ, lastBitMask, roundBitsMask;
    union ui32_f32 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    exp = expF32UI( uiA );
    

    if ( exp <= 0x7E ) {
        if ( !(uint32_t) (uiA<<1) ) return a;
        if ( exact ) softfloat_exceptionFlags |= softfloat_flag_inexact;
        uiZ = uiA & packToF32UI( 1, 0, 0 );
        switch ( roundingMode ) {
         case softfloat_round_near_even:
            if ( !fracF32UI( uiA ) ) break;
             
            fallthrough;
         case softfloat_round_near_maxMag:
            if ( exp == 0x7E ) uiZ |= packToF32UI( 0, 0x7F, 0 );
            break;
         case softfloat_round_min:
            if ( uiZ ) uiZ = packToF32UI( 1, 0x7F, 0 );
            break;
         case softfloat_round_max:
            if ( !uiZ ) uiZ = packToF32UI( 0, 0x7F, 0 );
            break;
#ifdef SOFTFLOAT_ROUND_ODD
         case softfloat_round_odd:
            uiZ |= packToF32UI( 0, 0x7F, 0 );
            break;
#endif
        }
        goto uiZ;
    }
    

    if ( 0x96 <= exp ) {
        if ( (exp == 0xFF) && fracF32UI( uiA ) ) {
            uiZ = softfloat_propagateNaNF32UI( uiA, 0 );
            goto uiZ;
        }
        return a;
    }
    

    uiZ = uiA;
    lastBitMask = (uint_fast32_t) 1<<(0x96 - exp);
    roundBitsMask = lastBitMask - 1;
    if ( roundingMode == softfloat_round_near_maxMag ) {
        uiZ += lastBitMask>>1;
    } else if ( roundingMode == softfloat_round_near_even ) {
        uiZ += lastBitMask>>1;
        if ( !(uiZ & roundBitsMask) ) uiZ &= ~lastBitMask;
    } else if (
        roundingMode
            == (signF32UI( uiZ ) ? softfloat_round_min : softfloat_round_max)
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