/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _I64_TO_F64_C_INCLUDED_
#define _I64_TO_F64_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float64_t i64_to_f64( int64_t a )
{
    bool sign;
    union ui64_f64 uZ;
    uint_fast64_t absA;

    sign = (a < 0);
    if ( ! (a & UINT64_C( 0x7FFFFFFFFFFFFFFF )) ) {
        uZ.ui = sign ? packToF64UI( 1, 0x43E, 0 ) : 0;
        return uZ.f;
    }
    absA = sign ? -(uint_fast64_t) a : (uint_fast64_t) a;
    return softfloat_normRoundPackToF64( sign, 0x43C, absA );

}

#endif   