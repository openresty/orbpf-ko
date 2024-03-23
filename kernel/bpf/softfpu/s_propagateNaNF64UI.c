/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_PROPAGATENANF64UI_C_INCLUDED_
#define _S_PROPAGATENANF64UI_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"







uint_fast64_t
static inline softfloat_propagateNaNF64UI( uint_fast64_t uiA, uint_fast64_t uiB )
{
    bool isSigNaNA, isSigNaNB;
    uint_fast64_t uiNonsigA, uiNonsigB, uiMagA, uiMagB;

    

    isSigNaNA = softfloat_isSigNaNF64UI( uiA );
    isSigNaNB = softfloat_isSigNaNF64UI( uiB );
    


    uiNonsigA = uiA | UINT64_C( 0x0008000000000000 );
    uiNonsigB = uiB | UINT64_C( 0x0008000000000000 );
    

    if ( isSigNaNA | isSigNaNB ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        if ( isSigNaNA ) {
            if ( isSigNaNB ) goto returnLargerMag;
            return isNaNF64UI( uiB ) ? uiNonsigB : uiNonsigA;
        } else {
            return isNaNF64UI( uiA ) ? uiNonsigA : uiNonsigB;
        }
    }
 returnLargerMag:
    uiMagA = uiA & UINT64_C( 0x7FFFFFFFFFFFFFFF );
    uiMagB = uiB & UINT64_C( 0x7FFFFFFFFFFFFFFF );
    if ( uiMagA < uiMagB ) return uiNonsigB;
    if ( uiMagB < uiMagA ) return uiNonsigA;
    return (uiNonsigA < uiNonsigB) ? uiNonsigA : uiNonsigB;

}

#endif   