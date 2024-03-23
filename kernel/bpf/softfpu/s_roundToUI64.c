/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include <linux/types.h>
#include "platform.h"
#include "internals.h"
#include "specialize.h"
#include "softfloat.h"

uint_fast64_t
 softfloat_roundToUI64(
     bool sign,
     uint_fast64_t sig,
     uint_fast64_t sigExtra,
     uint_fast8_t roundingMode,
     bool exact
 )
{

    

    if (
        (roundingMode == softfloat_round_near_maxMag)
            || (roundingMode == softfloat_round_near_even)
    ) {
        if ( UINT64_C( 0x8000000000000000 ) <= sigExtra ) goto increment;
    } else {
        if ( sign ) {
            if ( !(sig | sigExtra) ) return 0;
            if ( roundingMode == softfloat_round_min ) goto invalid;
#ifdef SOFTFLOAT_ROUND_ODD
            if ( roundingMode == softfloat_round_odd ) goto invalid;
#endif
        } else {
            if ( (roundingMode == softfloat_round_max) && sigExtra ) {
 increment:
                ++sig;
                if ( !sig ) goto invalid;
                if (
                    (sigExtra == UINT64_C( 0x8000000000000000 ))
                        && (roundingMode == softfloat_round_near_even)
                ) {
                    sig &= ~(uint_fast64_t) 1;
                }
            }
        }
    }
    if ( sign && sig ) goto invalid;
    if ( sigExtra ) {
#ifdef SOFTFLOAT_ROUND_ODD
        if ( roundingMode == softfloat_round_odd ) sig |= 1;
#endif
        if ( exact ) softfloat_exceptionFlags |= softfloat_flag_inexact;
    }
    return sig;
    

 invalid:
    softfloat_raiseFlags( softfloat_flag_invalid );
    return sign ? ui64_fromNegOverflow : ui64_fromPosOverflow;

}