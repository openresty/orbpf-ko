/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_REM_C_INCLUDED_
#define _F32_REM_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float32_t f32_rem( float32_t a, float32_t b )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast32_t sigA;
    union ui32_f32 uB;
    uint_fast32_t uiB;
    int_fast16_t expB;
    uint_fast32_t sigB;
    struct exp16_sig32 normExpSig;
    uint32_t rem;
    int_fast16_t expDiff;
    uint32_t q, recip32, altRem, meanRem;
    bool signRem;
    uint_fast32_t uiZ;
    union ui32_f32 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    signA = signF32UI( uiA );
    expA  = expF32UI( uiA );
    sigA  = fracF32UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    expB = expF32UI( uiB );
    sigB = fracF32UI( uiB );
    

    if ( expA == 0xFF ) {
        if ( sigA || ((expB == 0xFF) && sigB) ) goto propagateNaN;
        goto invalid;
    }
    if ( expB == 0xFF ) {
        if ( sigB ) goto propagateNaN;
        return a;
    }
    

    if ( ! expB ) {
        if ( ! sigB ) goto invalid;
        normExpSig = softfloat_normSubnormalF32Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if ( ! expA ) {
        if ( ! sigA ) return a;
        normExpSig = softfloat_normSubnormalF32Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    

    rem = sigA | 0x00800000;
    sigB |= 0x00800000;
    expDiff = expA - expB;
    if ( expDiff < 1 ) {
        if ( expDiff < -1 ) return a;
        sigB <<= 6;
        if ( expDiff ) {
            rem <<= 5;
            q = 0;
        } else {
            rem <<= 6;
            q = (sigB <= rem);
            if ( q ) rem -= sigB;
        }
    } else {
        recip32 = softfloat_approxRecip32_1( sigB<<8 );
        



        rem <<= 7;
        expDiff -= 31;
        




        sigB <<= 6;
        for (;;) {
            q = (rem * (uint_fast64_t) recip32)>>32;
            if ( expDiff < 0 ) break;
            rem = -(q * (uint32_t) sigB);
            expDiff -= 29;
        }
        


        q >>= ~expDiff & 31;
        rem = (rem<<(expDiff + 30)) - q * (uint32_t) sigB;
    }
    

    do {
        altRem = rem;
        ++q;
        rem -= sigB;
    } while ( ! (rem & 0x80000000) );
    meanRem = rem + altRem;
    if ( (meanRem & 0x80000000) || (! meanRem && (q & 1)) ) rem = altRem;
    signRem = signA;
    if ( 0x80000000 <= rem ) {
        signRem = ! signRem;
        rem = -rem;
    }
    return softfloat_normRoundPackToF32( signRem, expB, rem );
    

 propagateNaN:
    uiZ = softfloat_propagateNaNF32UI( uiA, uiB );
    goto uiZ;
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF32UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   