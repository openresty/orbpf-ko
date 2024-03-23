/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_sub128

struct uint128
 softfloat_sub128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
{
    struct uint128 z;

    z.v0 = a0 - b0;
    z.v64 = a64 - b64 - (a0 < b0);
    return z;

}

#endif