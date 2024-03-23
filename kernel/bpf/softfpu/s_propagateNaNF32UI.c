/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_PROPAGATENANF32UI_C_INCLUDED_
#define _S_PROPAGATENANF32UI_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"







uint_fast32_t
static inline softfloat_propagateNaNF32UI( uint_fast32_t uiA, uint_fast32_t uiB )
{
    bool isSigNaNA, isSigNaNB;
    uint_fast32_t uiNonsigA, uiNonsigB, uiMagA, uiMagB;

    

    isSigNaNA = softfloat_isSigNaNF32UI( uiA );
    isSigNaNB = softfloat_isSigNaNF32UI( uiB );
    


    uiNonsigA = uiA | 0x00400000;
    uiNonsigB = uiB | 0x00400000;
    

    if ( isSigNaNA | isSigNaNB ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        if ( isSigNaNA ) {
            if ( isSigNaNB ) goto returnLargerMag;
            return isNaNF32UI( uiB ) ? uiNonsigB : uiNonsigA;
        } else {
            return isNaNF32UI( uiA ) ? uiNonsigA : uiNonsigB;
        }
    }
 returnLargerMag:
    uiMagA = uiA & 0x7FFFFFFF;
    uiMagB = uiB & 0x7FFFFFFF;
    if ( uiMagA < uiMagB ) return uiNonsigB;
    if ( uiMagB < uiMagA ) return uiNonsigA;
    return (uiNonsigA < uiNonsigB) ? uiNonsigA : uiNonsigB;

}

#endif   