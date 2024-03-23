/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _UI32_TO_F32_C_INCLUDED_
#define _UI32_TO_F32_C_INCLUDED_

#include "platform.h"
#include "internals.h"
#include "softfloat.h"

static inline
float32_t ui32_to_f32( uint32_t a )
{
    union ui32_f32 uZ;

    if ( ! a ) {
        uZ.ui = 0;
        return uZ.f;
    }
    if ( a & 0x80000000 ) {
        return softfloat_roundPackToF32( 0, 0x9D, a>>1 | (a & 1) );
    } else {
        return softfloat_normRoundPackToF32( 0, 0x9C, a );
    }

}

#endif   