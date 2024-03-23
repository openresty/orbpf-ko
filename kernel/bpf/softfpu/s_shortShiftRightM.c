/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftRightM

void
 softfloat_shortShiftRightM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 )
{
    uint_fast8_t uNegDist;
    unsigned int index, lastIndex;
    uint32_t partWordZ, wordA;

    uNegDist = -dist;
    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    partWordZ = aPtr[index]>>dist;
    while ( index != lastIndex ) {
        wordA = aPtr[index + wordIncr];
        zPtr[index] = wordA<<(uNegDist & 31) | partWordZ;
        index += wordIncr;
        partWordZ = wordA>>dist;
    }
    zPtr[index] = partWordZ;

}

#endif