/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_ADD_C_INCLUDED_
#define _F64_ADD_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float64_t f64_add( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    bool signA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signB;
#if ! defined INLINE_LEVEL || (INLINE_LEVEL < 2)
    float64_t (*magsFuncPtr)( uint_fast64_t, uint_fast64_t, bool );
#endif

    uA.f = a;
    uiA = uA.ui;
    signA = signF64UI( uiA );
    uB.f = b;
    uiB = uB.ui;
    signB = signF64UI( uiB );
#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
    if ( signA == signB ) {
        return softfloat_addMagsF64( uiA, uiB, signA );
    } else {
        return softfloat_subMagsF64( uiA, uiB, signA );
    }
#else
    magsFuncPtr =
        (signA == signB) ? softfloat_addMagsF64 : softfloat_subMagsF64;
    return (*magsFuncPtr)( uiA, uiB, signA );
#endif

}

#endif   