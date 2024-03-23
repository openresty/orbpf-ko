/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_shiftRightJam256M

static
 void
  softfloat_shortShiftRightJamM(
      uint_fast8_t size_words,
      const uint64_t *aPtr,
      uint_fast8_t dist,
      uint64_t *zPtr
  )
{
    uint_fast8_t uNegDist;
    unsigned int index, lastIndex;
    uint64_t partWordZ, wordA;

    uNegDist = -dist;
    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    wordA = aPtr[index];
    partWordZ = wordA>>dist;
    if ( partWordZ<<dist != wordA ) partWordZ |= 1;
    while ( index != lastIndex ) {
        wordA = aPtr[index + wordIncr];
        zPtr[index] = wordA<<(uNegDist & 63) | partWordZ;
        index += wordIncr;
        partWordZ = wordA>>dist;
    }
    zPtr[index] = partWordZ;

}

void
 softfloat_shiftRightJam256M(
     const uint64_t *aPtr, uint_fast32_t dist, uint64_t *zPtr )
{
    uint64_t wordJam;
    uint_fast32_t wordDist;
    uint64_t *ptr;
    uint_fast8_t i, innerDist;

    wordJam = 0;
    wordDist = dist>>6;
    if ( wordDist ) {
        if ( 4 < wordDist ) wordDist = 4;
        ptr = (uint64_t *) (aPtr + indexMultiwordLo( 4, wordDist ));
        i = wordDist;
        do {
            wordJam = *ptr++;
            if ( wordJam ) break;
            --i;
        } while ( i );
        ptr = zPtr;
    }
    if ( wordDist < 4 ) {
        aPtr += indexMultiwordHiBut( 4, wordDist );
        innerDist = dist & 63;
        if ( innerDist ) {
            softfloat_shortShiftRightJamM(
                4 - wordDist,
                aPtr,
                innerDist,
                zPtr + indexMultiwordLoBut( 4, wordDist )
            );
            if ( ! wordDist ) goto wordJam;
        } else {
            aPtr += indexWordLo( 4 - wordDist );
            ptr = zPtr + indexWordLo( 4 );
            for ( i = 4 - wordDist; i; --i ) {
                *ptr = *aPtr;
                aPtr += wordIncr;
                ptr += wordIncr;
            }
        }
        ptr = zPtr + indexMultiwordHi( 4, wordDist );
    }
    do {
        *ptr++ = 0;
        --wordDist;
    } while ( wordDist );
 wordJam:
    if ( wordJam ) zPtr[indexWordLo( 4 )] |= 1;

}

#endif