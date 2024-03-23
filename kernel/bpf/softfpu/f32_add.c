/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_ADD_C_INCLUDED_
#define _F32_ADD_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float32_t f32_add( float32_t a, float32_t b )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    union ui32_f32 uB;
    uint_fast32_t uiB;
#if ! defined INLINE_LEVEL || (INLINE_LEVEL < 1)
    float32_t (*magsFuncPtr)( uint_fast32_t, uint_fast32_t );
#endif

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
#if defined INLINE_LEVEL && (1 <= INLINE_LEVEL)
    if ( signF32UI( uiA ^ uiB ) ) {
        return softfloat_subMagsF32( uiA, uiB );
    } else {
        return softfloat_addMagsF32( uiA, uiB );
    }
#else
    magsFuncPtr =
        signF32UI( uiA ^ uiB ) ? softfloat_subMagsF32 : softfloat_addMagsF32;
    return (*magsFuncPtr)( uiA, uiB );
#endif

}

#endif   