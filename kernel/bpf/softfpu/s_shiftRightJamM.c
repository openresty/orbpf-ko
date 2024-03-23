/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _S_SHIFTRIGHTJAMM_C_INCLUDED_
#define _S_SHIFTRIGHTJAMM_C_INCLUDED_

#include "platform.h"

#ifndef softfloat_shiftRightJamM

#define softfloat_shiftRightJamM softfloat_shiftRightJamM
#include "primitives.h"

void
 softfloat_shiftRightJamM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 )
{
    uint32_t wordJam, wordDist, *ptr = NULL;
    uint_fast8_t i, innerDist;

    wordJam = 0;
    wordDist = dist>>5;
    if ( wordDist ) {
        if ( size_words < wordDist ) wordDist = size_words;
        ptr = (uint32_t *) (aPtr + indexMultiwordLo( size_words, wordDist ));
        i = wordDist;
        do {
            wordJam = *ptr++;
            if ( wordJam ) break;
            --i;
        } while ( i );
        ptr = zPtr;
    }
    if ( wordDist < size_words ) {
        aPtr += indexMultiwordHiBut( size_words, wordDist );
        innerDist = dist & 31;
        if ( innerDist ) {
            softfloat_shortShiftRightJamM(
                size_words - wordDist,
                aPtr,
                innerDist,
                zPtr + indexMultiwordLoBut( size_words, wordDist )
            );
            if ( ! wordDist ) goto wordJam;
        } else {
            aPtr += indexWordLo( size_words - wordDist );
            ptr = zPtr + indexWordLo( size_words );
            for ( i = size_words - wordDist; i; --i ) {
                *ptr = *aPtr;
                aPtr += wordIncr;
                ptr += wordIncr;
            }
        }
        ptr = zPtr + indexMultiwordHi( size_words, wordDist );
    }
    do {
        *ptr++ = 0;
        --wordDist;
    } while ( wordDist );
 wordJam:
    if ( wordJam ) zPtr[indexWordLo( size_words )] |= 1;

}

#endif

#endif   