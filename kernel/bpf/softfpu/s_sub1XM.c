/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_sub1XM

void softfloat_sub1XM( uint_fast8_t size_words, uint32_t *zPtr )
{
    unsigned int index, lastIndex;
    uint32_t wordA;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    for (;;) {
        wordA = zPtr[index];
        zPtr[index] = wordA - 1;
        if ( wordA || (index == lastIndex) ) break;
        index += wordIncr;
    }

}

#endif