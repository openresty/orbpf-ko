/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_COUNTlEADINGzEROS32_1_C_INCLUDED_
#define _S_COUNTlEADINGzEROS32_1_C_INCLUDED_


#include "platform.h"

#ifndef softfloat_countLeadingZeros32

#define softfloat_countLeadingZeros32 softfloat_countLeadingZeros32
#include "primitives.h"

INLINE
uint_fast8_t softfloat_countLeadingZeros32( uint32_t a )
{
    uint_fast8_t count;

    count = 0;
    if ( a < 0x10000 ) {
        count = 16;
        a <<= 16;
    }
    if ( a < 0x1000000 ) {
        count += 8;
        a <<= 8;
    }
    count += softfloat_countLeadingZeros8[a>>24];
    return count;

}

#endif


#endif   