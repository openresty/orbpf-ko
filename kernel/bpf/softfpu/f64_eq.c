/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_EQ_C_INCLUDED_
#define _F64_EQ_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
bool f64_eq( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    union ui64_f64 uB;
    uint_fast64_t uiB;

    uA.f = a;
    uiA = uA.ui;
    uB.f = b;
    uiB = uB.ui;
    if ( isNaNF64UI( uiA ) || isNaNF64UI( uiB ) ) {
        if (
            softfloat_isSigNaNF64UI( uiA ) || softfloat_isSigNaNF64UI( uiB )
        ) {
            softfloat_raiseFlags( softfloat_flag_invalid );
        }
        return false;
    }
    return (uiA == uiB) || ! ((uiA | uiB) & UINT64_C( 0x7FFFFFFFFFFFFFFF ));

}

#endif   