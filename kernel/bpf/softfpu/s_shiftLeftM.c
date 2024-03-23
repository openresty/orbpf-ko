/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"

#ifndef softfloat_shiftLeftM

#define softfloat_shiftLeftM softfloat_shiftLeftM
#include "primitives.h"

void
 softfloat_shiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 )
{
    uint32_t wordDist;
    uint_fast8_t innerDist;
    uint32_t *destPtr;
    uint_fast8_t i;

    wordDist = dist>>5;
    if ( wordDist < size_words ) {
        aPtr += indexMultiwordLoBut( size_words, wordDist );
        innerDist = dist & 31;
        if ( innerDist ) {
            softfloat_shortShiftLeftM(
                size_words - wordDist,
                aPtr,
                innerDist,
                zPtr + indexMultiwordHiBut( size_words, wordDist )
            );
            if ( ! wordDist ) return;
        } else {
            aPtr += indexWordHi( size_words - wordDist );
            destPtr = zPtr + indexWordHi( size_words );
            for ( i = size_words - wordDist; i; --i ) {
                *destPtr = *aPtr;
                aPtr -= wordIncr;
                destPtr -= wordIncr;
            }
        }
        zPtr += indexMultiwordLo( size_words, wordDist );
    } else {
        wordDist = size_words;
    }
    do {
        *zPtr++ = 0;
        --wordDist;
    } while ( wordDist );

}

#endif