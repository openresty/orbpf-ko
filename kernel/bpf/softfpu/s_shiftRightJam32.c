/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _SOFTFLOAT_SHIFTRIGHTJAM32_C_INCLUDED_
#define _SOFTFLOAT_SHIFTRIGHTJAM32_C_INCLUDED_

#include "platform.h"


uint32_t softfloat_shiftRightJam32( uint32_t a, uint_fast16_t dist )
{

    return
        (dist < 31) ? a>>dist | ((uint32_t) (a<<(-dist & 31)) != 0) : (a != 0);

}

#endif   