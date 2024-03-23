/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _SOFTFLOAT_STATE_C_INCLUDED_
#define _SOFTFLOAT_STATE_C_INCLUDED_

#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

#ifndef THREAD_LOCAL
#define THREAD_LOCAL
#endif

THREAD_LOCAL uint_fast8_t softfloat_roundingMode = softfloat_round_near_even;
THREAD_LOCAL uint_fast8_t softfloat_detectTininess = init_detectTininess;
THREAD_LOCAL uint_fast8_t softfloat_exceptionFlags = 0;

THREAD_LOCAL uint_fast8_t extF80_roundingPrecision = 80;

#endif   