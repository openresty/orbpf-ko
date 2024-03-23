/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _UI64_TO_F64_C_INCLUDED_
#define _UI64_TO_F64_C_INCLUDED_

#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float64_t ui64_to_f64( uint64_t a )
{
    union ui64_f64 uZ;

    if ( ! a ) {
        uZ.ui = 0;
        return uZ.f;
    }
    if ( a & UINT64_C( 0x8000000000000000 ) ) {
        return
            softfloat_roundPackToF64(
                0, 0x43D, softfloat_shortShiftRightJam64( a, 1 ) );
    } else {
        return softfloat_normRoundPackToF64( 0, 0x43C, a );
    }

}

#endif   