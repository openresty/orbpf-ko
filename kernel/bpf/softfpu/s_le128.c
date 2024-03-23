/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include <linux/types.h>
#include "platform.h"

#ifndef softfloat_le128

bool softfloat_le128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
{

    return (a64 < b64) || ((a64 == b64) && (a0 <= b0));

}

#endif