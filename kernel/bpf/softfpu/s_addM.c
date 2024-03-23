/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_addM

void
 softfloat_addM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 )
{
    unsigned int index, lastIndex;
    uint_fast8_t carry;
    uint32_t wordA, wordZ;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    carry = 0;
    for (;;) {
        wordA = aPtr[index];
        wordZ = wordA + bPtr[index] + carry;
        zPtr[index] = wordZ;
        if ( index == lastIndex ) break;
        if ( wordZ != wordA ) carry = (wordZ < wordA);
        index += wordIncr;
    }

}

#endif