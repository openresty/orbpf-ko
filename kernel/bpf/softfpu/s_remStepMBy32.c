/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_remStepMBy32

void
 softfloat_remStepMBy32(
     uint_fast8_t size_words,
     const uint32_t *remPtr,
     uint_fast8_t dist,
     const uint32_t *bPtr,
     uint32_t q,
     uint32_t *zPtr
 )
{
    unsigned int index, lastIndex;
    uint64_t dwordProd;
    uint32_t wordRem, wordShiftedRem, wordProd;
    uint_fast8_t uNegDist, borrow;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    dwordProd = (uint64_t) bPtr[index] * q;
    wordRem = remPtr[index];
    wordShiftedRem = wordRem<<dist;
    wordProd = dwordProd;
    zPtr[index] = wordShiftedRem - wordProd;
    if ( index != lastIndex ) {
        uNegDist = -dist;
        borrow = (wordShiftedRem < wordProd);
        for (;;) {
            wordShiftedRem = wordRem>>(uNegDist & 31);
            index += wordIncr;
            dwordProd = (uint64_t) bPtr[index] * q + (dwordProd>>32);
            wordRem = remPtr[index];
            wordShiftedRem |= wordRem<<dist;
            wordProd = dwordProd;
            zPtr[index] = wordShiftedRem - wordProd - borrow;
            if ( index == lastIndex ) break;
            borrow =
                borrow ? (wordShiftedRem <= wordProd)
                    : (wordShiftedRem < wordProd);
        }
    }

}

#endif