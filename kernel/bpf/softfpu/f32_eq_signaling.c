/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

bool f32_eq_signaling( float32_t a, float32_t b )
{
    union ui32_f32 uA;
    uint_fast32_t uiA;
    union ui32_f32 uB;
    uint_fast32_t uiB;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    if ( isNaNF32UI( uiA ) || isNaNF32UI( uiB ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
        return false;
    }
    return (uiA == uiB) || ! (uint32_t) ((uiA | uiB)<<1);

}