/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_APPROXRECIP32_1_C_INCLUDED_
#define _S_APPROXRECIP32_1_C_INCLUDED_

#include "platform.h"

#ifndef softfloat_approxRecip32_1

extern const uint16_t softfloat_approxRecip_1k0s[16];
extern const uint16_t softfloat_approxRecip_1k1s[16];

static inline
uint32_t softfloat_approxRecip32_1( uint32_t a )
{
    int index;
    uint16_t eps, r0;
    uint32_t sigma0;
    uint_fast32_t r;
    uint32_t sqrSigma0;

    index = a>>27 & 0xF;
    eps = (uint16_t) (a>>11);
    r0 = softfloat_approxRecip_1k0s[index]
             - ((softfloat_approxRecip_1k1s[index] * (uint_fast32_t) eps)>>20);
    sigma0 = ~(uint_fast32_t) ((r0 * (uint_fast64_t) a)>>7);
    r = ((uint_fast32_t) r0<<16) + ((r0 * (uint_fast64_t) sigma0)>>24);
    sqrSigma0 = ((uint_fast64_t) sigma0 * sigma0)>>32;
    r += ((uint32_t) r * (uint_fast64_t) sqrSigma0)>>48;
    return r;

}

#endif

#endif   