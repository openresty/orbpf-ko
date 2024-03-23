/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_negXM

void softfloat_negXM( uint_fast8_t size_words, uint32_t *zPtr )
{
    unsigned int index, lastIndex;
    uint_fast8_t carry;
    uint32_t word;

    index = indexWordLo( size_words );
    lastIndex = indexWordHi( size_words );
    carry = 1;
    for (;;) {
        word = ~zPtr[index] + carry;
        zPtr[index] = word;
        if ( index == lastIndex ) break;
        index += wordIncr;
        if ( word ) carry = 0;
    }

}

#endif