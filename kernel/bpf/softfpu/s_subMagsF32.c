/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_SUBMAGSF32_C_INCLUDED_
#define _S_SUBMAGSF32_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
float32_t softfloat_subMagsF32( uint_fast32_t uiA, uint_fast32_t uiB )
{
    int_fast16_t expA;
    uint_fast32_t sigA;
    int_fast16_t expB;
    uint_fast32_t sigB;
    int_fast16_t expDiff;
    uint_fast32_t uiZ;
    int_fast32_t sigDiff;
    bool signZ;
    int_fast8_t shiftDist;
    int_fast16_t expZ;
    uint_fast32_t sigX, sigY;
    union ui32_f32 uZ;

    

    expA = expF32UI( uiA );
    sigA = fracF32UI( uiA );
    expB = expF32UI( uiB );
    sigB = fracF32UI( uiB );
    

    expDiff = expA - expB;
    if ( ! expDiff ) {
        

        if ( expA == 0xFF ) {
            if ( sigA | sigB ) goto propagateNaN;
            softfloat_raiseFlags( softfloat_flag_invalid );
            uiZ = defaultNaNF32UI;
            goto uiZ;
        }
        sigDiff = sigA - sigB;
        if ( ! sigDiff ) {
            uiZ =
                packToF32UI(
                    (softfloat_roundingMode == softfloat_round_min), 0, 0 );
            goto uiZ;
        }
        if ( expA ) --expA;
        signZ = signF32UI( uiA );
        if ( sigDiff < 0 ) {
            signZ = ! signZ;
            sigDiff = -sigDiff;
        }
        shiftDist = softfloat_countLeadingZeros32( sigDiff ) - 8;
        expZ = expA - shiftDist;
        if ( expZ < 0 ) {
            shiftDist = expA;
            expZ = 0;
        }
        uiZ = packToF32UI( signZ, expZ, sigDiff<<shiftDist );
        goto uiZ;
    } else {
        

        signZ = signF32UI( uiA );
        sigA <<= 7;
        sigB <<= 7;
        if ( expDiff < 0 ) {
            

            signZ = ! signZ;
            if ( expB == 0xFF ) {
                if ( sigB ) goto propagateNaN;
                uiZ = packToF32UI( signZ, 0xFF, 0 );
                goto uiZ;
            }
            expZ = expB - 1;
            sigX = sigB | 0x40000000;
            sigY = sigA + (expA ? 0x40000000 : sigA);
            expDiff = -expDiff;
        } else {
            

            if ( expA == 0xFF ) {
                if ( sigA ) goto propagateNaN;
                uiZ = uiA;
                goto uiZ;
            }
            expZ = expA - 1;
            sigX = sigA | 0x40000000;
            sigY = sigB + (expB ? 0x40000000 : sigB);
        }
        return
            softfloat_normRoundPackToF32(
                signZ, expZ, sigX - softfloat_shiftRightJam32( sigY, expDiff )
            );
    }
    

 propagateNaN:
    uiZ = softfloat_propagateNaNF32UI( uiA, uiB );
 uiZ:
    uZ.ui = uiZ;
    return uZ.f;

}

#endif   