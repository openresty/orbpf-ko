/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_COMMONNANTOF32UI_C_INCLUDED_
#define _S_COMMONNANTOF32UI_C_INCLUDED_

#include <linux/types.h>
#include "platform.h"
#include "specialize.h"





static inline uint_fast32_t softfloat_commonNaNToF32UI( const struct commonNaN *aPtr )
{

    return (uint_fast32_t) aPtr->sign<<31 | 0x7FC00000 | aPtr->v64>>41;

}

#endif   