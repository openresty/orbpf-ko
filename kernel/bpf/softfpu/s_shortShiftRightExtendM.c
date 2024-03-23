/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftRightExtendM

void
 softfloat_shortShiftRightExtendM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 )
{
    uint_fast8_t uNegDist;
    unsigned int indexA, lastIndexA;
    uint32_t partWordZ, wordA;

    uNegDist = -dist;
    indexA = indexWordLo( size_words );
    lastIndexA = indexWordHi( size_words );
    zPtr += indexWordLo( size_words + 1 );
    partWordZ = 0;
    for (;;) {
        wordA = aPtr[indexA];
        *zPtr = wordA<<(uNegDist & 31) | partWordZ;
        zPtr += wordIncr;
        partWordZ = wordA>>dist;
        if ( indexA == lastIndexA ) break;
        indexA += wordIncr;
    }
    *zPtr = partWordZ;

}

#endif