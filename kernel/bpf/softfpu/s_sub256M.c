/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_sub256M

void
 softfloat_sub256M(
     const uint64_t *aPtr, const uint64_t *bPtr, uint64_t *zPtr )
{
    unsigned int index;
    uint_fast8_t borrow;
    uint64_t wordA, wordB;

    index = indexWordLo( 4 );
    borrow = 0;
    for (;;) {
        wordA = aPtr[index];
        wordB = bPtr[index];
        zPtr[index] = wordA - wordB - borrow;
        if ( index == indexWordHi( 4 ) ) break;
        borrow = borrow ? (wordA <= wordB) : (wordA < wordB);
        index += wordIncr;
    }

}

#endif