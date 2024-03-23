/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_SQRT_C_INCLUDED_
#define _F64_SQRT_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float64_t f64_sqrt( float64_t a )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA, uiZ;
    struct exp16_sig64 normExpSig;
    int_fast16_t expZ;
    uint32_t sig32A, recipSqrt32, sig32Z;
    uint_fast64_t rem;
    uint32_t q;
    uint_fast64_t sigZ, shiftedSigZ;
    union ui64_f64 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    

    if ( expA == 0x7FF ) {
        if ( sigA ) {
            uiZ = softfloat_propagateNaNF64UI( uiA, 0 );
            goto uiZ;
        }
        if ( ! signA ) return a;
        goto invalid;
    }
    

    if ( signA ) {
        if ( ! (expA | sigA) ) return a;
        goto invalid;
    }
    

    if ( ! expA ) {
        if ( ! sigA ) return a;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    




    expZ = ((expA - 0x3FF)>>1) + 0x3FE;
    expA &= 1;
    sigA |= UINT64_C( 0x0010000000000000 );
    sig32A = sigA>>21;
    recipSqrt32 = softfloat_approxRecipSqrt32_1( expA, sig32A );
    sig32Z = ((uint_fast64_t) sig32A * recipSqrt32)>>32;
    if ( expA ) {
        sigA <<= 8;
        sig32Z >>= 1;
    } else {
        sigA <<= 9;
    }
    rem = sigA - (uint_fast64_t) sig32Z * sig32Z;
    q = ((uint32_t) (rem>>2) * (uint_fast64_t) recipSqrt32)>>32;
    sigZ = ((uint_fast64_t) sig32Z<<32 | 1<<5) + ((uint_fast64_t) q<<3);
    

    if ( (sigZ & 0x1FF) < 0x22 ) {
        sigZ &= ~(uint_fast64_t) 0x3F;
        shiftedSigZ = sigZ>>6;
        rem = (sigA<<52) - shiftedSigZ * shiftedSigZ;
        if ( rem & UINT64_C( 0x8000000000000000 ) ) {
            --sigZ;
        } else {
            if ( rem ) sigZ |= 1;
        }
    }
    return softfloat_roundPackToF64( 0, expZ, sigZ );
    

 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   