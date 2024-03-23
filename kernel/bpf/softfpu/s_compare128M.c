/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_compare128M

int_fast8_t softfloat_compare128M( const uint32_t *aPtr, const uint32_t *bPtr )
{
    unsigned int index, lastIndex;
    uint32_t wordA, wordB;

    index = indexWordHi( 4 );
    lastIndex = indexWordLo( 4 );
    for (;;) {
        wordA = aPtr[index];
        wordB = bPtr[index];
        if ( wordA != wordB ) return (wordA < wordB) ? -1 : 1;
        if ( index == lastIndex ) break;
        index -= wordIncr;
    }
    return 0;

}

#endif