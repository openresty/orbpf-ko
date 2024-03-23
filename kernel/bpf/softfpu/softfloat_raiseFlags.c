/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _SOFTFLOAT_RAISEFLAGS_C_INCLUDED_
#define _SOFTFLOAT_RAISEFLAGS_C_INCLUDED_

#include "platform.h"
#include "softfloat.h"








static inline
void softfloat_raiseFlags( uint_fast8_t flags )
{

    softfloat_exceptionFlags |= flags;

}

#endif   