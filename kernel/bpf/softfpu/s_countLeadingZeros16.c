/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"

#ifndef softfloat_countLeadingZeros16

#define softfloat_countLeadingZeros16 softfloat_countLeadingZeros16
#include "primitives.h"

uint_fast8_t softfloat_countLeadingZeros16( uint16_t a )
{
    uint_fast8_t count;

    count = 8;
    if ( 0x100 <= a ) {
        count = 0;
        a >>= 8;
    }
    count += softfloat_countLeadingZeros8[a];
    return count;

}

#endif