/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_DIV_C_INCLUDED_
#define _F32_DIV_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float32_t f32_div( float32_t a, float32_t b )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast32_t sigA;
    union ui32_f32 uB;
    uint_fast32_t uiB;
    bool signB;
    int_fast16_t expB;
    uint_fast32_t sigB;
    bool signZ;
    struct exp16_sig32 normExpSig;
    int_fast16_t expZ;
#ifdef SOFTFLOAT_FAST_DIV64TO32
    uint_fast64_t sig64A;
    uint_fast32_t sigZ;
#else
    uint_fast32_t sigZ;
    uint_fast64_t rem;
#endif
    uint_fast32_t uiZ;
    union ui32_f32 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    signA = signF32UI( uiA );
    expA  = expF32UI( uiA );
    sigA  = fracF32UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    signB = signF32UI( uiB );
    expB  = expF32UI( uiB );
    sigB  = fracF32UI( uiB );
    signZ = signA ^ signB;
    

    if ( expA == 0xFF ) {
        if ( sigA ) goto propagateNaN;
        if ( expB == 0xFF ) {
            if ( sigB ) goto propagateNaN;
            goto invalid;
        }
        goto infinity;
    }
    if ( expB == 0xFF ) {
        if ( sigB ) goto propagateNaN;
        goto zero;
    }
    

    if ( ! expB ) {
        if ( ! sigB ) {
            if ( ! (expA | sigA) ) goto invalid;
            softfloat_raiseFlags( softfloat_flag_infinite );
            goto infinity;
        }
        normExpSig = softfloat_normSubnormalF32Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if ( ! expA ) {
        if ( ! sigA ) goto zero;
        normExpSig = softfloat_normSubnormalF32Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    

    expZ = expA - expB + 0x7E;
    sigA |= 0x00800000;
    sigB |= 0x00800000;
#ifdef SOFTFLOAT_FAST_DIV64TO32
    if ( sigA < sigB ) {
        --expZ;
        sig64A = (uint_fast64_t) sigA<<31;
    } else {
        sig64A = (uint_fast64_t) sigA<<30;
    }
    sigZ = sig64A / sigB;
    if ( ! (sigZ & 0x3F) ) sigZ |= ((uint_fast64_t) sigB * sigZ != sig64A);
#else
    if ( sigA < sigB ) {
        --expZ;
        sigA <<= 8;
    } else {
        sigA <<= 7;
    }
    sigB <<= 8;
    sigZ = ((uint_fast64_t) sigA * softfloat_approxRecip32_1( sigB ))>>32;
    

    sigZ += 2;
    if ( (sigZ & 0x3F) < 2 ) {
        sigZ &= ~3;
#ifdef SOFTFLOAT_FAST_INT64
        rem = ((uint_fast64_t) sigA<<31) - (uint_fast64_t) sigZ * sigB;
#else
        rem = ((uint_fast64_t) sigA<<32) - (uint_fast64_t) (sigZ<<1) * sigB;
#endif
        if ( rem & UINT64_C( 0x8000000000000000 ) ) {
            sigZ -= 4;
        } else {
            if ( rem ) sigZ |= 1;
        }
    }
#endif
    return softfloat_roundPackToF32( signZ, expZ, sigZ );
    

 propagateNaN:
    uiZ = softfloat_propagateNaNF32UI( uiA, uiB );
    goto uiZ;
    

 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF32UI;
    goto uiZ;
    

 infinity:
    uiZ = packToF32UI( signZ, 0xFF, 0 );
    goto uiZ;
    

 zero:
    uiZ = packToF32UI( signZ, 0, 0 );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   