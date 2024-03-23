/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_SHORTSHIFTRIGHTJAM64_C_INCLUDED_
#define _S_SHORTSHIFTRIGHTJAM64_C_INCLUDED_

#include "platform.h"

#ifndef softfloat_shortShiftRightJam64

static inline
uint64_t softfloat_shortShiftRightJam64( uint64_t a, uint_fast8_t dist )
{

    return a>>dist | ((a & (((uint_fast64_t) 1<<dist) - 1)) != 0);

}

#endif

#endif   