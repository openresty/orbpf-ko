/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_F64UITOCOMMONNAN_C_INCLUDED_
#define _S_F64UITOCOMMONNAN_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "specialize.h"
#include "softfloat.h"







static inline void softfloat_f64UIToCommonNaN( uint_fast64_t uiA, struct commonNaN *zPtr )
{

    if ( softfloat_isSigNaNF64UI( uiA ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
    }
    zPtr->sign = uiA>>63;
    zPtr->v64  = uiA<<12;
    zPtr->v0   = 0;

}

#endif   