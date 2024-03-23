/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_add256M

void
 softfloat_add256M(
     const uint64_t *aPtr, const uint64_t *bPtr, uint64_t *zPtr )
{
    unsigned int index;
    uint_fast8_t carry;
    uint64_t wordA, wordZ;

    index = indexWordLo( 4 );
    carry = 0;
    for (;;) {
        wordA = aPtr[index];
        wordZ = wordA + bPtr[index] + carry;
        zPtr[index] = wordZ;
        if ( index == indexWordHi( 4 ) ) break;
        if ( wordZ != wordA ) carry = (wordZ < wordA);
        index += wordIncr;
    }

}

#endif