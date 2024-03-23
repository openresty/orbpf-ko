/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include <linux/types.h>
#include "platform.h"
#include "specialize.h"

#ifndef _S_COMMONnAntOf64ui_C_INCLUDED_
#define _S_COMMONnAntOf64ui_C_INCLUDED_





static inline uint_fast64_t softfloat_commonNaNToF64UI( const struct commonNaN *aPtr )
{

    return
        (uint_fast64_t) aPtr->sign<<63 | UINT64_C( 0x7FF8000000000000 )
            | aPtr->v64>>12;

}

#endif   