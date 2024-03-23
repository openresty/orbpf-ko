/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F32_LE_QUIET_C_INCLUDED_
#define _F32_LE_QUIET_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
bool f32_le_quiet( float32_t a, float32_t b )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    union ui32_f32 uB;
    uint_fast32_t uiB;
    bool signA, signB;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    if ( isNaNF32UI( uiA ) || isNaNF32UI( uiB ) ) {
        if (
            softfloat_isSigNaNF32UI( uiA ) || softfloat_isSigNaNF32UI( uiB )
        ) {
            softfloat_raiseFlags( softfloat_flag_invalid );
        }
        return false;
    }
    signA = signF32UI( uiA );
    signB = signF32UI( uiB );
    return
        (signA != signB) ? signA || ! (uint32_t) ((uiA | uiB)<<1)
            : (uiA == uiB) || (signA ^ (uiA < uiB));

}

#endif   