/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#include "platform.h"
#include "primitiveTypes.h"

#ifndef softfloat_mul128MTo256M

void
 softfloat_mul128MTo256M(
     const uint32_t *aPtr, const uint32_t *bPtr, uint32_t *zPtr )
{
    uint32_t *lastZPtr, wordB;
    uint64_t dwordProd;
    uint32_t wordZ;
    uint_fast8_t carry;

    bPtr += indexWordLo( 4 );
    lastZPtr = zPtr + indexMultiwordHi( 8, 5 );
    zPtr += indexMultiwordLo( 8, 5 );
    wordB = *bPtr;
    dwordProd = (uint64_t) aPtr[indexWord( 4, 0 )] * wordB;
    zPtr[indexWord( 5, 0 )] = dwordProd;
    dwordProd = (uint64_t) aPtr[indexWord( 4, 1 )] * wordB + (dwordProd>>32);
    zPtr[indexWord( 5, 1 )] = dwordProd;
    dwordProd = (uint64_t) aPtr[indexWord( 4, 2 )] * wordB + (dwordProd>>32);
    zPtr[indexWord( 5, 2 )] = dwordProd;
    dwordProd = (uint64_t) aPtr[indexWord( 4, 3 )] * wordB + (dwordProd>>32);
    zPtr[indexWord( 5, 3 )] = dwordProd;
    zPtr[indexWord( 5, 4 )] = dwordProd>>32;
    do {
        bPtr += wordIncr;
        zPtr += wordIncr;
        wordB = *bPtr;
        dwordProd = (uint64_t) aPtr[indexWord( 4, 0 )] * wordB;
        wordZ = zPtr[indexWord( 5, 0 )] + (uint32_t) dwordProd;
        zPtr[indexWord( 5, 0 )] = wordZ;
        carry = (wordZ < (uint32_t) dwordProd);
        dwordProd =
            (uint64_t) aPtr[indexWord( 4, 1 )] * wordB + (dwordProd>>32);
        wordZ = zPtr[indexWord( 5, 1 )] + (uint32_t) dwordProd + carry;
        zPtr[indexWord( 5, 1 )] = wordZ;
        if ( wordZ != (uint32_t) dwordProd ) {
            carry = (wordZ < (uint32_t) dwordProd);
        }
        dwordProd =
            (uint64_t) aPtr[indexWord( 4, 2 )] * wordB + (dwordProd>>32);
        wordZ = zPtr[indexWord( 5, 2 )] + (uint32_t) dwordProd + carry;
        zPtr[indexWord( 5, 2 )] = wordZ;
        if ( wordZ != (uint32_t) dwordProd ) {
            carry = (wordZ < (uint32_t) dwordProd);
        }
        dwordProd =
            (uint64_t) aPtr[indexWord( 4, 3 )] * wordB + (dwordProd>>32);
        wordZ = zPtr[indexWord( 5, 3 )] + (uint32_t) dwordProd + carry;
        zPtr[indexWord( 5, 3 )] = wordZ;
        if ( wordZ != (uint32_t) dwordProd ) {
            carry = (wordZ < (uint32_t) dwordProd);
        }
        zPtr[indexWord( 5, 4 )] = (dwordProd>>32) + carry;
    } while ( zPtr != lastZPtr );

}

#endif