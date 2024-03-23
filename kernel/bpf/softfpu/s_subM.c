/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_subM

void
 softfloat_subM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 )
{
    unsigned int index, lastIndex;
    uint_fast8_t borrow;
    uint32_t wordA, wordB;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    borrow = 0;
    for (;;) {
        wordA = aPtr[index];
        wordB = bPtr[index];
        zPtr[index] = wordA - wordB - borrow;
        if ( index == lastIndex ) break;
        borrow = borrow ? (wordA <= wordB) : (wordA < wordB);
        index += wordIncr;
    }

}

#endif