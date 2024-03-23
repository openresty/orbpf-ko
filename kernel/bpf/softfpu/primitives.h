/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef _PRIMITIVES_H_INCLUDED_
#define _PRIMITIVES_H_INCLUDED_

#ifndef primitives_h
#define primitives_h 1

#include <linux/types.h>
#include "primitiveTypes.h"

#ifndef softfloat_shortShiftRightJam64






#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE

static inline
uint64_t softfloat_shortShiftRightJam64( uint64_t a, uint_fast8_t dist )
    { return a>>dist | ((a & (((uint_fast64_t) 1<<dist) - 1)) != 0); }
#else
static inline uint64_t softfloat_shortShiftRightJam64( uint64_t a, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shiftRightJam32









#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)

static inline
uint32_t softfloat_shiftRightJam32( uint32_t a, uint_fast16_t dist )
{
    return
        (dist < 31) ? a>>dist | ((uint32_t) (a<<(-dist & 31)) != 0) : (a != 0);
}
#else
uint32_t softfloat_shiftRightJam32( uint32_t a, uint_fast16_t dist );
#endif
#endif

#ifndef softfloat_shiftRightJam64









#if defined INLINE_LEVEL && (3 <= INLINE_LEVEL)

static inline
uint64_t softfloat_shiftRightJam64( uint64_t a, uint_fast32_t dist )
{
    return
        (dist < 63) ? a>>dist | ((uint64_t) (a<<(-dist & 63)) != 0) : (a != 0);
}
#else
static inline uint64_t softfloat_shiftRightJam64( uint64_t a, uint_fast32_t dist );
#endif
#endif






extern const uint_least8_t softfloat_countLeadingZeros8[256];

#ifndef softfloat_countLeadingZeros16




#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)

static inline
uint_fast8_t softfloat_countLeadingZeros16( uint16_t a )
{
    uint_fast8_t count = 8;
    if ( 0x100 <= a ) {
        count = 0;
        a >>= 8;
    }
    count += softfloat_countLeadingZeros8[a];
    return count;
}
#else
uint_fast8_t softfloat_countLeadingZeros16( uint16_t a );
#endif
#endif

#ifndef softfloat_countLeadingZeros32




#if defined INLINE_LEVEL && (3 <= INLINE_LEVEL)

INLINE
uint_fast8_t softfloat_countLeadingZeros32( uint32_t a )
{
    uint_fast8_t count = 0;
    if ( a < 0x10000 ) {
        count = 16;
        a <<= 16;
    }
    if ( a < 0x1000000 ) {
        count += 8;
        a <<= 8;
    }
    count += softfloat_countLeadingZeros8[a>>24];
    return count;
}
#else
INLINE uint_fast8_t softfloat_countLeadingZeros32( uint32_t a );
#endif
#endif

#ifndef softfloat_countLeadingZeros64




uint_fast8_t softfloat_countLeadingZeros64( uint64_t a );
#endif

extern const uint16_t softfloat_approxRecip_1k0s[16];
extern const uint16_t softfloat_approxRecip_1k1s[16];

#ifndef softfloat_approxRecip32_1











#ifdef SOFTFLOAT_FAST_DIV64TO32
#define softfloat_approxRecip32_1( a ) ((uint32_t) (UINT64_C( 0x7FFFFFFFFFFFFFFF ) / (uint32_t) (a)))
#else
static inline uint32_t softfloat_approxRecip32_1( uint32_t a );
#endif
#endif

extern const uint16_t softfloat_approxRecipSqrt_1k0s[16];
extern const uint16_t softfloat_approxRecipSqrt_1k1s[16];

#ifndef softfloat_approxRecipSqrt32_1


















static inline uint32_t softfloat_approxRecipSqrt32_1( unsigned int oddExpA, uint32_t a );
#endif

#ifdef SOFTFLOAT_FAST_INT64






#ifndef softfloat_eq128





#if defined INLINE_LEVEL && (1 <= INLINE_LEVEL)
INLINE

static inline
bool softfloat_eq128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
    { return (a64 == b64) && (a0 == b0); }
#else
bool softfloat_eq128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 );
#endif
#endif

#ifndef softfloat_le128





#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE

static inline
bool softfloat_le128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
    { return (a64 < b64) || ((a64 == b64) && (a0 <= b0)); }
#else
bool softfloat_le128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 );
#endif
#endif

#ifndef softfloat_lt128





#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE

static inline
bool softfloat_lt128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
    { return (a64 < b64) || ((a64 == b64) && (a0 < b0)); }
#else
bool softfloat_lt128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 );
#endif
#endif

#ifndef softfloat_shortShiftLeft128




#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
struct uint128
 softfloat_shortShiftLeft128( uint64_t a64, uint64_t a0, uint_fast8_t dist )
{
    struct uint128 z;
    z.v64 = a64<<dist | a0>>(-dist & 63);
    z.v0 = a0<<dist;
    return z;
}
#else
struct uint128
 softfloat_shortShiftLeft128( uint64_t a64, uint64_t a0, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shortShiftRight128




#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
struct uint128
 softfloat_shortShiftRight128( uint64_t a64, uint64_t a0, uint_fast8_t dist )
{
    struct uint128 z;
    z.v64 = a64>>dist;
    z.v0 = a64<<(-dist & 63) | a0>>dist;
    return z;
}
#else
struct uint128
 softfloat_shortShiftRight128( uint64_t a64, uint64_t a0, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shortShiftRightJam64Extra




#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
struct uint64_extra
 softfloat_shortShiftRightJam64Extra(
     uint64_t a, uint64_t extra, uint_fast8_t dist )
{
    struct uint64_extra z;
    z.v = a>>dist;
    z.extra = a<<(-dist & 63) | (extra != 0);
    return z;
}
#else
struct uint64_extra
 softfloat_shortShiftRightJam64Extra(
     uint64_t a, uint64_t extra, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shortShiftRightJam128







#if defined INLINE_LEVEL && (3 <= INLINE_LEVEL)
INLINE
struct uint128
 softfloat_shortShiftRightJam128(
     uint64_t a64, uint64_t a0, uint_fast8_t dist )
{
    uint_fast8_t negDist = -dist;
    struct uint128 z;
    z.v64 = a64>>dist;
    z.v0 =
        a64<<(negDist & 63) | a0>>dist
            | ((uint64_t) (a0<<(negDist & 63)) != 0);
    return z;
}
#else
struct uint128
 softfloat_shortShiftRightJam128(
     uint64_t a64, uint64_t a0, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shortShiftRightJam128Extra




#if defined INLINE_LEVEL && (3 <= INLINE_LEVEL)
INLINE
struct uint128_extra
 softfloat_shortShiftRightJam128Extra(
     uint64_t a64, uint64_t a0, uint64_t extra, uint_fast8_t dist )
{
    uint_fast8_t negDist = -dist;
    struct uint128_extra z;
    z.v.v64 = a64>>dist;
    z.v.v0 = a64<<(negDist & 63) | a0>>dist;
    z.extra = a0<<(negDist & 63) | (extra != 0);
    return z;
}
#else
struct uint128_extra
 softfloat_shortShiftRightJam128Extra(
     uint64_t a64, uint64_t a0, uint64_t extra, uint_fast8_t dist );
#endif
#endif

#ifndef softfloat_shiftRightJam64Extra
















#if defined INLINE_LEVEL && (4 <= INLINE_LEVEL)
INLINE
struct uint64_extra
 softfloat_shiftRightJam64Extra(
     uint64_t a, uint64_t extra, uint_fast32_t dist )
{
    struct uint64_extra z;
    if ( dist < 64 ) {
        z.v = a>>dist;
        z.extra = a<<(-dist & 63);
    } else {
        z.v = 0;
        z.extra = (dist == 64) ? a : (a != 0);
    }
    z.extra |= (extra != 0);
    return z;
}
#else
struct uint64_extra
 softfloat_shiftRightJam64Extra(
     uint64_t a, uint64_t extra, uint_fast32_t dist );
#endif
#endif

#ifndef softfloat_shiftRightJam128










struct uint128
 softfloat_shiftRightJam128( uint64_t a64, uint64_t a0, uint_fast32_t dist );
#endif

#ifndef softfloat_shiftRightJam128Extra

















struct uint128_extra
 softfloat_shiftRightJam128Extra(
     uint64_t a64, uint64_t a0, uint64_t extra, uint_fast32_t dist );
#endif

#ifndef softfloat_shiftRightJam256M












void
 softfloat_shiftRightJam256M(
     const uint64_t *aPtr, uint_fast32_t dist, uint64_t *zPtr );
#endif

#ifndef softfloat_add128





#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
struct uint128
 softfloat_add128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
{
    struct uint128 z;
    z.v0 = a0 + b0;
    z.v64 = a64 + b64 + (z.v0 < a0);
    return z;
}
#else
struct uint128
 softfloat_add128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 );
#endif
#endif

#ifndef softfloat_add256M







void
 softfloat_add256M(
     const uint64_t *aPtr, const uint64_t *bPtr, uint64_t *zPtr );
#endif

#ifndef softfloat_sub128





#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
struct uint128
 softfloat_sub128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 )
{
    struct uint128 z;
    z.v0 = a0 - b0;
    z.v64 = a64 - b64;
    z.v64 -= (a0 < b0);
    return z;
}
#else
struct uint128
 softfloat_sub128( uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0 );
#endif
#endif

#ifndef softfloat_sub256M








void
 softfloat_sub256M(
     const uint64_t *aPtr, const uint64_t *bPtr, uint64_t *zPtr );
#endif

#ifndef softfloat_mul64ByShifted32To128



#if defined INLINE_LEVEL && (3 <= INLINE_LEVEL)
INLINE struct uint128 softfloat_mul64ByShifted32To128( uint64_t a, uint32_t b )
{
    uint_fast64_t mid;
    struct uint128 z;
    mid = (uint_fast64_t) (uint32_t) a * b;
    z.v0 = mid<<32;
    z.v64 = (uint_fast64_t) (uint32_t) (a>>32) * b + (mid>>32);
    return z;
}
#else
struct uint128 softfloat_mul64ByShifted32To128( uint64_t a, uint32_t b );
#endif
#endif

#ifndef softfloat_mul64To128



struct uint128 softfloat_mul64To128( uint64_t a, uint64_t b );
#endif

#ifndef softfloat_mul128By32





#if defined INLINE_LEVEL && (4 <= INLINE_LEVEL)
INLINE
struct uint128 softfloat_mul128By32( uint64_t a64, uint64_t a0, uint32_t b )
{
    struct uint128 z;
    uint_fast64_t mid;
    uint_fast32_t carry;
    z.v0 = a0 * b;
    mid = (uint_fast64_t) (uint32_t) (a0>>32) * b;
    carry = (uint32_t) ((uint_fast32_t) (z.v0>>32) - (uint_fast32_t) mid);
    z.v64 = a64 * b + (uint_fast32_t) ((mid + carry)>>32);
    return z;
}
#else
struct uint128 softfloat_mul128By32( uint64_t a64, uint64_t a0, uint32_t b );
#endif
#endif

#ifndef softfloat_mul128To256M







void
 softfloat_mul128To256M(
     uint64_t a64, uint64_t a0, uint64_t b64, uint64_t b0, uint64_t *zPtr );
#endif

#else






#ifndef softfloat_compare96M








int_fast8_t softfloat_compare96M( const uint32_t *aPtr, const uint32_t *bPtr );
#endif

#ifndef softfloat_compare128M








int_fast8_t
 softfloat_compare128M( const uint32_t *aPtr, const uint32_t *bPtr );
#endif

#ifndef softfloat_shortShiftLeft64To96M







#if defined INLINE_LEVEL && (2 <= INLINE_LEVEL)
INLINE
void
 softfloat_shortShiftLeft64To96M(
     uint64_t a, uint_fast8_t dist, uint32_t *zPtr )
{
    zPtr[indexWord( 3, 0 )] = (uint32_t) a<<dist;
    a >>= 32 - dist;
    zPtr[indexWord( 3, 2 )] = a>>32;
    zPtr[indexWord( 3, 1 )] = a;
}
#else
void
 softfloat_shortShiftLeft64To96M(
     uint64_t a, uint_fast8_t dist, uint32_t *zPtr );
#endif
#endif

#ifndef softfloat_shortShiftLeftM









void
 softfloat_shortShiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shortShiftLeft96M




#define softfloat_shortShiftLeft96M( aPtr, dist, zPtr ) softfloat_shortShiftLeftM( 3, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftLeft128M




#define softfloat_shortShiftLeft128M( aPtr, dist, zPtr ) softfloat_shortShiftLeftM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftLeft160M




#define softfloat_shortShiftLeft160M( aPtr, dist, zPtr ) softfloat_shortShiftLeftM( 5, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftLeftM










void
 softfloat_shiftLeftM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shiftLeft96M




#define softfloat_shiftLeft96M( aPtr, dist, zPtr ) softfloat_shiftLeftM( 3, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftLeft128M




#define softfloat_shiftLeft128M( aPtr, dist, zPtr ) softfloat_shiftLeftM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftLeft160M




#define softfloat_shiftLeft160M( aPtr, dist, zPtr ) softfloat_shiftLeftM( 5, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftRightM









void
 softfloat_shortShiftRightM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint_fast8_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shortShiftRight128M




#define softfloat_shortShiftRight128M( aPtr, dist, zPtr ) softfloat_shortShiftRightM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftRight160M




#define softfloat_shortShiftRight160M( aPtr, dist, zPtr ) softfloat_shortShiftRightM( 5, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shortShiftRightJamM










void
 softfloat_shortShiftRightJamM(
     uint_fast8_t, const uint32_t *, uint_fast8_t, uint32_t * );
#endif

#ifndef softfloat_shortShiftRightJam160M




#define softfloat_shortShiftRightJam160M( aPtr, dist, zPtr ) softfloat_shortShiftRightJamM( 5, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftRightM










void
 softfloat_shiftRightM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shiftRight96M




#define softfloat_shiftRight96M( aPtr, dist, zPtr ) softfloat_shiftRightM( 3, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftRightJamM













void
 softfloat_shiftRightJamM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     uint32_t dist,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_shiftRightJam96M




#define softfloat_shiftRightJam96M( aPtr, dist, zPtr ) softfloat_shiftRightJamM( 3, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftRightJam128M




#define softfloat_shiftRightJam128M( aPtr, dist, zPtr ) softfloat_shiftRightJamM( 4, aPtr, dist, zPtr )
#endif

#ifndef softfloat_shiftRightJam160M




#define softfloat_shiftRightJam160M( aPtr, dist, zPtr ) softfloat_shiftRightJamM( 5, aPtr, dist, zPtr )
#endif

#ifndef softfloat_addM








void
 softfloat_addM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_add96M




#define softfloat_add96M( aPtr, bPtr, zPtr ) softfloat_addM( 3, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_add128M




#define softfloat_add128M( aPtr, bPtr, zPtr ) softfloat_addM( 4, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_add160M




#define softfloat_add160M( aPtr, bPtr, zPtr ) softfloat_addM( 5, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_addCarryM








uint_fast8_t
 softfloat_addCarryM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint_fast8_t carry,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_addComplCarryM





uint_fast8_t
 softfloat_addComplCarryM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint_fast8_t carry,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_addComplCarry96M




#define softfloat_addComplCarry96M( aPtr, bPtr, carry, zPtr ) softfloat_addComplCarryM( 3, aPtr, bPtr, carry, zPtr )
#endif

#ifndef softfloat_negXM






void softfloat_negXM( uint_fast8_t size_words, uint32_t *zPtr );
#endif

#ifndef softfloat_negX96M




#define softfloat_negX96M( zPtr ) softfloat_negXM( 3, zPtr )
#endif

#ifndef softfloat_negX128M




#define softfloat_negX128M( zPtr ) softfloat_negXM( 4, zPtr )
#endif

#ifndef softfloat_negX160M




#define softfloat_negX160M( zPtr ) softfloat_negXM( 5, zPtr )
#endif

#ifndef softfloat_negX256M




#define softfloat_negX256M( zPtr ) softfloat_negXM( 8, zPtr )
#endif

#ifndef softfloat_sub1XM







void softfloat_sub1XM( uint_fast8_t size_words, uint32_t *zPtr );
#endif

#ifndef softfloat_sub1X96M




#define softfloat_sub1X96M( zPtr ) softfloat_sub1XM( 3, zPtr )
#endif

#ifndef softfloat_sub1X160M




#define softfloat_sub1X160M( zPtr ) softfloat_sub1XM( 5, zPtr )
#endif

#ifndef softfloat_subM








void
 softfloat_subM(
     uint_fast8_t size_words,
     const uint32_t *aPtr,
     const uint32_t *bPtr,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_sub96M




#define softfloat_sub96M( aPtr, bPtr, zPtr ) softfloat_subM( 3, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_sub128M




#define softfloat_sub128M( aPtr, bPtr, zPtr ) softfloat_subM( 4, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_sub160M




#define softfloat_sub160M( aPtr, bPtr, zPtr ) softfloat_subM( 5, aPtr, bPtr, zPtr )
#endif

#ifndef softfloat_mul64To128M






static inline void softfloat_mul64To128M( uint64_t a, uint64_t b, uint32_t *zPtr );
#endif

#ifndef softfloat_mul128MTo256M








void
 softfloat_mul128MTo256M(
     const uint32_t *aPtr, const uint32_t *bPtr, uint32_t *zPtr );
#endif

#ifndef softfloat_remStepMBy32









void
 softfloat_remStepMBy32(
     uint_fast8_t size_words,
     const uint32_t *remPtr,
     uint_fast8_t dist,
     const uint32_t *bPtr,
     uint32_t q,
     uint32_t *zPtr
 );
#endif

#ifndef softfloat_remStep96MBy32




#define softfloat_remStep96MBy32( remPtr, dist, bPtr, q, zPtr ) softfloat_remStepMBy32( 3, remPtr, dist, bPtr, q, zPtr )
#endif

#ifndef softfloat_remStep128MBy32




#define softfloat_remStep128MBy32( remPtr, dist, bPtr, q, zPtr ) softfloat_remStepMBy32( 4, remPtr, dist, bPtr, q, zPtr )
#endif

#ifndef softfloat_remStep160MBy32




#define softfloat_remStep160MBy32( remPtr, dist, bPtr, q, zPtr ) softfloat_remStepMBy32( 5, remPtr, dist, bPtr, q, zPtr )
#endif

#endif

#endif

#endif   