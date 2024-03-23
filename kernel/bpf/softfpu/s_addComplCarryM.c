/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_addComplCarryM

uint_fast8_t
 softfloat_addComplCarryM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint_fast8_t carry,
     uint32_t *zPtr
 )
{
    unsigned int index, lastIndex;
    uint32_t wordA, wordZ;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    for (;;) {
        wordA = aPtr[index];
        wordZ = wordA + ~bPtr[index] + carry;
        zPtr[index] = wordZ;
        if ( wordZ != wordA ) carry = (wordZ < wordA);
        if ( index == lastIndex ) break;
        index += wordIncr;
    }
    return carry;

}

#endif