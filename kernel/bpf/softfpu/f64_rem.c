/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_REM_C_INCLUDED_
#define _F64_REM_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float64_t f64_rem( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    int_fast16_t expA;
    uint_fast64_t sigA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    int_fast16_t expB;
    uint_fast64_t sigB;
    struct exp16_sig64 normExpSig;
    uint64_t rem;
    int_fast16_t expDiff;
    uint32_t q, recip32;
    uint_fast64_t q64;
    uint64_t altRem, meanRem;
    bool signRem;
    uint_fast64_t uiZ;
    union ui64_f64 uZ;

    

    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    expA  = expF64UI( uiA );
    sigA  = fracF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    expB = expF64UI( uiB );
    sigB = fracF64UI( uiB );
    

    if ( expA == 0x7FF ) {
        if ( sigA || ((expB == 0x7FF) && sigB) ) goto propagateNaN;
        goto invalid;
    }
    if ( expB == 0x7FF ) {
        if ( sigB ) goto propagateNaN;
        return a;
    }
    

    if ( expA < expB - 1 ) return a;
    

    if ( ! expB ) {
        if ( ! sigB ) goto invalid;
        normExpSig = softfloat_normSubnormalF64Sig( sigB );
        expB = normExpSig.exp;
        sigB = normExpSig.sig;
    }
    if ( ! expA ) {
        if ( ! sigA ) return a;
        normExpSig = softfloat_normSubnormalF64Sig( sigA );
        expA = normExpSig.exp;
        sigA = normExpSig.sig;
    }
    

    rem = sigA | UINT64_C( 0x0010000000000000 );
    sigB |= UINT64_C( 0x0010000000000000 );
    expDiff = expA - expB;
    if ( expDiff < 1 ) {
        if ( expDiff < -1 ) return a;
        sigB <<= 9;
        if ( expDiff ) {
            rem <<= 8;
            q = 0;
        } else {
            rem <<= 9;
            q = (sigB <= rem);
            if ( q ) rem -= sigB;
        }
    } else {
        recip32 = softfloat_approxRecip32_1( sigB>>21 );
        



        rem <<= 9;
        expDiff -= 30;
        




        sigB <<= 9;
        for (;;) {
            q64 = (uint32_t) (rem>>32) * (uint_fast64_t) recip32;
            if ( expDiff < 0 ) break;
            q = (q64 + 0x80000000)>>32;
#ifdef SOFTFLOAT_FAST_INT64
            rem <<= 29;
#else
            rem = (uint_fast64_t) (uint32_t) (rem>>3)<<32;
#endif
            rem -= q * (uint64_t) sigB;
            if ( rem & UINT64_C( 0x8000000000000000 ) ) rem += sigB;
            expDiff -= 29;
        }
        


        q = (uint32_t) (q64>>32)>>(~expDiff & 31);
        rem = (rem<<(expDiff + 30)) - q * (uint64_t) sigB;
        if ( rem & UINT64_C( 0x8000000000000000 ) ) {
            altRem = rem + sigB;
            goto selectRem;
        }
    }
    

    do {
        altRem = rem;
        ++q;
        rem -= sigB;
    } while ( ! (rem & UINT64_C( 0x8000000000000000 )) );
 selectRem:
    meanRem = rem + altRem;
    if (
        (meanRem & UINT64_C( 0x8000000000000000 )) || (! meanRem && (q & 1))
    ) {
        rem = altRem;
    }
    signRem = signA;
    if ( rem & UINT64_C( 0x8000000000000000 ) ) {
        signRem = ! signRem;
        rem = -rem;
    }
    return softfloat_normRoundPackToF64( signRem, expB, rem );
    

 propagateNaN:
    uiZ = softfloat_propagateNaNF64UI( uiA, uiB );
    goto uiZ;
 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    uiZ = defaultNaNF64UI;
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   