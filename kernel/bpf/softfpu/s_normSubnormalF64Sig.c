/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_NORMSUBNORMALF64SIG_C_INCLUDED_
#define _S_NORMSUBNORMALF64SIG_C_INCLUDED_

#include "platform.h"
#include "internals.h"

static inline
struct exp16_sig64 softfloat_normSubnormalF64Sig( uint_fast64_t sig )
{
    int_fast8_t shiftDist;
    struct exp16_sig64 z;

    shiftDist = softfloat_countLeadingZeros64( sig ) - 11;
    z.exp = 1 - shiftDist;
    z.sig = sig<<shiftDist;
    return z;

}

#endif   