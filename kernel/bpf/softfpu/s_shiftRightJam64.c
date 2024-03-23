/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_SHIFTRIGHTJAM64_C_INCLUDED_
#define _S_SHIFTRIGHTJAM64_C_INCLUDED_

#include "platform.h"

#ifndef softfloat_shiftRightJam64

static inline
uint64_t softfloat_shiftRightJam64( uint64_t a, uint_fast32_t dist )
{

    return
        (dist < 63) ? a>>dist | ((uint64_t) (a<<(-dist & 63)) != 0) : (a != 0);

}

#endif

#endif   