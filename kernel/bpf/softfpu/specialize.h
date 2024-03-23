/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef specialize_h
#define specialize_h 1

#include <linux/types.h>
#include "primitiveTypes.h"
#include "softfloat.h"




#define init_detectTininess softfloat_tininess_afterRounding





#define ui32_fromPosOverflow 0xFFFFFFFF
#define ui32_fromNegOverflow 0xFFFFFFFF
#define ui32_fromNaN         0xFFFFFFFF
#define i32_fromPosOverflow  (-0x7FFFFFFF - 1)
#define i32_fromNegOverflow  (-0x7FFFFFFF - 1)
#define i32_fromNaN          (-0x7FFFFFFF - 1)





#define ui64_fromPosOverflow UINT64_C( 0xFFFFFFFFFFFFFFFF )
#define ui64_fromNegOverflow UINT64_C( 0xFFFFFFFFFFFFFFFF )
#define ui64_fromNaN         UINT64_C( 0xFFFFFFFFFFFFFFFF )
#define i64_fromPosOverflow  (-INT64_C( 0x7FFFFFFFFFFFFFFF ) - 1)
#define i64_fromNegOverflow  (-INT64_C( 0x7FFFFFFFFFFFFFFF ) - 1)
#define i64_fromNaN          (-INT64_C( 0x7FFFFFFFFFFFFFFF ) - 1)





struct commonNaN {
    bool sign;
#ifdef LITTLEENDIAN
    uint64_t v0, v64;
#else
    uint64_t v64, v0;
#endif
};




#define defaultNaNF16UI 0xFE00






#define softfloat_isSigNaNF16UI( uiA ) ((((uiA) & 0x7E00) == 0x7C00) && ((uiA) & 0x01FF))







void softfloat_f16UIToCommonNaN( uint_fast16_t uiA, struct commonNaN *zPtr );





uint_fast16_t softfloat_commonNaNToF16UI( const struct commonNaN *aPtr );







uint_fast16_t
 softfloat_propagateNaNF16UI( uint_fast16_t uiA, uint_fast16_t uiB );




#define defaultNaNF32UI 0xFFC00000






#define softfloat_isSigNaNF32UI( uiA ) ((((uiA) & 0x7FC00000) == 0x7F800000) && ((uiA) & 0x003FFFFF))







static inline void softfloat_f32UIToCommonNaN( uint_fast32_t uiA, struct commonNaN *zPtr );





static inline uint_fast32_t softfloat_commonNaNToF32UI( const struct commonNaN *aPtr );







static inline uint_fast32_t
 softfloat_propagateNaNF32UI( uint_fast32_t uiA, uint_fast32_t uiB );




#define defaultNaNF64UI UINT64_C( 0xFFF8000000000000 )






#define softfloat_isSigNaNF64UI( uiA ) ((((uiA) & UINT64_C( 0x7FF8000000000000 )) == UINT64_C( 0x7FF0000000000000 )) && ((uiA) & UINT64_C( 0x0007FFFFFFFFFFFF )))







static inline void softfloat_f64UIToCommonNaN( uint_fast64_t uiA, struct commonNaN *zPtr );





static inline uint_fast64_t softfloat_commonNaNToF64UI( const struct commonNaN *aPtr );







static inline uint_fast64_t
 softfloat_propagateNaNF64UI( uint_fast64_t uiA, uint_fast64_t uiB );




#define defaultNaNExtF80UI64 0xFFFF
#define defaultNaNExtF80UI0  UINT64_C( 0xC000000000000000 )







#define softfloat_isSigNaNExtF80UI( uiA64, uiA0 ) ((((uiA64) & 0x7FFF) == 0x7FFF) && ! ((uiA0) & UINT64_C( 0x4000000000000000 )) && ((uiA0) & UINT64_C( 0x3FFFFFFFFFFFFFFF )))

#ifdef SOFTFLOAT_FAST_INT64













void
 softfloat_extF80UIToCommonNaN(
     uint_fast16_t uiA64, uint_fast64_t uiA0, struct commonNaN *zPtr );






struct uint128 softfloat_commonNaNToExtF80UI( const struct commonNaN *aPtr );










struct uint128
 softfloat_propagateNaNExtF80UI(
     uint_fast16_t uiA64,
     uint_fast64_t uiA0,
     uint_fast16_t uiB64,
     uint_fast64_t uiB0
 );




#define defaultNaNF128UI64 UINT64_C( 0xFFFF800000000000 )
#define defaultNaNF128UI0  UINT64_C( 0 )







#define softfloat_isSigNaNF128UI( uiA64, uiA0 ) ((((uiA64) & UINT64_C( 0x7FFF800000000000 )) == UINT64_C( 0x7FFF000000000000 )) && ((uiA0) || ((uiA64) & UINT64_C( 0x00007FFFFFFFFFFF ))))








void
 softfloat_f128UIToCommonNaN(
     uint_fast64_t uiA64, uint_fast64_t uiA0, struct commonNaN *zPtr );





struct uint128 softfloat_commonNaNToF128UI( const struct commonNaN * );










struct uint128
 softfloat_propagateNaNF128UI(
     uint_fast64_t uiA64,
     uint_fast64_t uiA0,
     uint_fast64_t uiB64,
     uint_fast64_t uiB0
 );

#else












void
 softfloat_extF80MToCommonNaN(
     const struct extFloat80M *aSPtr, struct commonNaN *zPtr );






void
 softfloat_commonNaNToExtF80M(
     const struct commonNaN *aPtr, struct extFloat80M *zSPtr );







void
 softfloat_propagateNaNExtF80M(
     const struct extFloat80M *aSPtr,
     const struct extFloat80M *bSPtr,
     struct extFloat80M *zSPtr
 );




#define defaultNaNF128UI96 0xFFFF8000
#define defaultNaNF128UI64 0
#define defaultNaNF128UI32 0
#define defaultNaNF128UI0  0









void
 softfloat_f128MToCommonNaN( const uint32_t *aWPtr, struct commonNaN *zPtr );







void
 softfloat_commonNaNToF128M( const struct commonNaN *aPtr, uint32_t *zWPtr );









void
 softfloat_propagateNaNF128M(
     const uint32_t *aWPtr, const uint32_t *bWPtr, uint32_t *zWPtr );

#endif

#endif