/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_NORMsUBNORMALf32sIG_C_INCLUDED_
#define _S_NORMsUBNORMALf32sIG_C_INCLUDED_

#include "platform.h"
#include "internals.h"

static inline struct exp16_sig32 softfloat_normSubnormalF32Sig( uint_fast32_t sig )
{
    int_fast8_t shiftDist;
    struct exp16_sig32 z;

    shiftDist = softfloat_countLeadingZeros32( sig ) - 8;
    z.exp = 1 - shiftDist;
    z.sig = sig<<shiftDist;
    return z;

}

#endif   