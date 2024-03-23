/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _F64_LT_QUIET_C_INCLUDED_
#define _F64_LT_QUIET_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

static inline
bool f64_lt_quiet( float64_t a, float64_t b )
{
    union ui64_f64 uA;
    uint_fast64_t uiA;
    union ui64_f64 uB;
    uint_fast64_t uiB;
    bool signA, signB;

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
    signA = signF64UI( uiA );
    signB = signF64UI( uiB );
    return
        (signA != signB)
            ? signA && ((uiA | uiB) & UINT64_C( 0x7FFFFFFFFFFFFFFF ))
            : (uiA != uiB) && (signA ^ (uiA < uiB));

}

#endif   