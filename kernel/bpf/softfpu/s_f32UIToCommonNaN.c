/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_F32UITOCOMMONNAN_C_INCLUDED_
#define _S_F32UITOCOMMONNAN_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "specialize.h"
#include "softfloat.h"







static inline void softfloat_f32UIToCommonNaN( uint_fast32_t uiA, struct commonNaN *zPtr )
{

    if ( softfloat_isSigNaNF32UI( uiA ) ) {
        softfloat_raiseFlags( softfloat_flag_invalid );
    }
    zPtr->sign = uiA>>31;
    zPtr->v64  = (uint_fast64_t) uiA<<41;
    zPtr->v0   = 0;

}

#endif   