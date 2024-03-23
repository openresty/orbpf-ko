/* Copyright (C) by OpenResty Inc. All rights reserved. */












































#ifndef softfloat_h
#define softfloat_h 1

#include <linux/types.h>
#include "softfloat_types.h"

#ifndef THREAD_LOCAL
#define THREAD_LOCAL
#endif




extern THREAD_LOCAL uint_fast8_t softfloat_detectTininess;
enum {
    softfloat_tininess_beforeRounding = 0,
    softfloat_tininess_afterRounding  = 1
};





extern THREAD_LOCAL uint_fast8_t softfloat_roundingMode;
enum {
    softfloat_round_near_even   = 0,
    softfloat_round_minMag      = 1,
    softfloat_round_min         = 2,
    softfloat_round_max         = 3,
    softfloat_round_near_maxMag = 4,
    softfloat_round_odd         = 6
};




extern THREAD_LOCAL uint_fast8_t softfloat_exceptionFlags;
enum {
    softfloat_flag_inexact   =  1,
    softfloat_flag_underflow =  2,
    softfloat_flag_overflow  =  4,
    softfloat_flag_infinite  =  8,
    softfloat_flag_invalid   = 16
};




static inline void softfloat_raiseFlags( uint_fast8_t );




float16_t ui32_to_f16( uint32_t );
static inline float32_t ui32_to_f32( uint32_t );
static inline float64_t ui32_to_f64( uint32_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t ui32_to_extF80( uint32_t );
float128_t ui32_to_f128( uint32_t );
#endif
void ui32_to_extF80M( uint32_t, extFloat80_t * );
void ui32_to_f128M( uint32_t, float128_t * );
float16_t ui64_to_f16( uint64_t );
static inline float32_t ui64_to_f32( uint64_t );
static inline float64_t ui64_to_f64( uint64_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t ui64_to_extF80( uint64_t );
float128_t ui64_to_f128( uint64_t );
#endif
void ui64_to_extF80M( uint64_t, extFloat80_t * );
void ui64_to_f128M( uint64_t, float128_t * );
float16_t i32_to_f16( int32_t );
static inline float32_t i32_to_f32( int32_t );
static inline float64_t i32_to_f64( int32_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t i32_to_extF80( int32_t );
float128_t i32_to_f128( int32_t );
#endif
void i32_to_extF80M( int32_t, extFloat80_t * );
void i32_to_f128M( int32_t, float128_t * );
float16_t i64_to_f16( int64_t );
static inline float32_t i64_to_f32( int64_t );
static inline float64_t i64_to_f64( int64_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t i64_to_extF80( int64_t );
float128_t i64_to_f128( int64_t );
#endif
void i64_to_extF80M( int64_t, extFloat80_t * );
void i64_to_f128M( int64_t, float128_t * );




uint_fast32_t f16_to_ui32( float16_t, uint_fast8_t, bool );
uint_fast64_t f16_to_ui64( float16_t, uint_fast8_t, bool );
int_fast32_t f16_to_i32( float16_t, uint_fast8_t, bool );
int_fast64_t f16_to_i64( float16_t, uint_fast8_t, bool );
uint_fast32_t f16_to_ui32_r_minMag( float16_t, bool );
uint_fast64_t f16_to_ui64_r_minMag( float16_t, bool );
int_fast32_t f16_to_i32_r_minMag( float16_t, bool );
int_fast64_t f16_to_i64_r_minMag( float16_t, bool );
float32_t f16_to_f32( float16_t );
float64_t f16_to_f64( float16_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t f16_to_extF80( float16_t );
float128_t f16_to_f128( float16_t );
#endif
void f16_to_extF80M( float16_t, extFloat80_t * );
void f16_to_f128M( float16_t, float128_t * );
float16_t f16_roundToInt( float16_t, uint_fast8_t, bool );
float16_t f16_add( float16_t, float16_t );
float16_t f16_sub( float16_t, float16_t );
float16_t f16_mul( float16_t, float16_t );
float16_t f16_mulAdd( float16_t, float16_t, float16_t );
float16_t f16_div( float16_t, float16_t );
float16_t f16_rem( float16_t, float16_t );
float16_t f16_sqrt( float16_t );
bool f16_eq( float16_t, float16_t );
bool f16_le( float16_t, float16_t );
bool f16_lt( float16_t, float16_t );
bool f16_eq_signaling( float16_t, float16_t );
bool f16_le_quiet( float16_t, float16_t );
bool f16_lt_quiet( float16_t, float16_t );
bool f16_isSignalingNaN( float16_t );




uint_fast32_t f32_to_ui32( float32_t, uint_fast8_t, bool );
uint_fast64_t f32_to_ui64( float32_t, uint_fast8_t, bool );
int_fast32_t f32_to_i32( float32_t, uint_fast8_t, bool );
int_fast64_t f32_to_i64( float32_t, uint_fast8_t, bool );
static inline uint_fast32_t f32_to_ui32_r_minMag( float32_t, bool );
static inline uint_fast64_t f32_to_ui64_r_minMag( float32_t, bool );
static inline int_fast32_t f32_to_i32_r_minMag( float32_t, bool );
static inline int_fast64_t f32_to_i64_r_minMag( float32_t, bool );
float16_t f32_to_f16( float32_t );
static inline float64_t f32_to_f64( float32_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t f32_to_extF80( float32_t );
float128_t f32_to_f128( float32_t );
#endif
void f32_to_extF80M( float32_t, extFloat80_t * );
void f32_to_f128M( float32_t, float128_t * );
static inline float32_t f32_roundToInt( float32_t, uint_fast8_t, bool );
static inline float32_t f32_add( float32_t, float32_t );
static inline float32_t f32_sub( float32_t, float32_t );
static inline float32_t f32_mul( float32_t, float32_t );
float32_t f32_mulAdd( float32_t, float32_t, float32_t );
static inline float32_t f32_div( float32_t, float32_t );
static inline float32_t f32_rem( float32_t, float32_t );
static inline float32_t f32_sqrt( float32_t );
static inline bool f32_eq( float32_t, float32_t );
bool f32_le( float32_t, float32_t );
bool f32_lt( float32_t, float32_t );
bool f32_eq_signaling( float32_t, float32_t );
static inline bool f32_le_quiet( float32_t, float32_t );
static inline bool f32_lt_quiet( float32_t, float32_t );
bool f32_isSignalingNaN( float32_t );

#ifndef f32_isneg
#define f32_isneg(u)        ((uint32_t) (u) & 0x80000000U)
#endif

#ifndef f32_abs
#define f32_abs(u)        ((uint32_t) (u) & ~0x80000000U)
#endif

#ifndef f32_neg
#define f32_neg(u)        ((uint32_t) (u) ^ 0x80000000U)
#endif




uint_fast32_t f64_to_ui32( float64_t, uint_fast8_t, bool );
static inline uint_fast64_t f64_to_ui64( float64_t, uint_fast8_t, bool );
int_fast32_t f64_to_i32( float64_t, uint_fast8_t, bool );
int_fast64_t f64_to_i64( float64_t, uint_fast8_t, bool );
static inline uint_fast32_t f64_to_ui32_r_minMag( float64_t, bool );
static inline uint_fast64_t f64_to_ui64_r_minMag( float64_t, bool );
static inline int_fast32_t f64_to_i32_r_minMag( float64_t, bool );
static inline int_fast64_t f64_to_i64_r_minMag( float64_t, bool );
float16_t f64_to_f16( float64_t );
static inline float32_t f64_to_f32( float64_t );
#ifdef SOFTFLOAT_FAST_INT64
extFloat80_t f64_to_extF80( float64_t );
float128_t f64_to_f128( float64_t );
#endif
void f64_to_extF80M( float64_t, extFloat80_t * );
void f64_to_f128M( float64_t, float128_t * );
static inline float64_t f64_roundToInt( float64_t, uint_fast8_t, bool );
static inline float64_t f64_add( float64_t, float64_t );
static inline float64_t f64_sub( float64_t, float64_t );
static inline float64_t f64_mul( float64_t, float64_t );
float64_t f64_mulAdd( float64_t, float64_t, float64_t );
static inline float64_t f64_div( float64_t, float64_t );
static inline float64_t f64_rem( float64_t, float64_t );
static inline float64_t f64_sqrt( float64_t );
static inline bool f64_eq( float64_t, float64_t );
bool f64_le( float64_t, float64_t );
bool f64_lt( float64_t, float64_t );
bool f64_eq_signaling( float64_t, float64_t );
static inline bool f64_le_quiet( float64_t, float64_t );
static inline bool f64_lt_quiet( float64_t, float64_t );
bool f64_isSignalingNaN( float64_t );

#ifndef f64_isneg
#define f64_isneg(u)        ((uint64_t) (u) & 0x8000000000000000UL)
#endif

#ifndef f64_abs
#define f64_abs(u)        ((uint64_t) (u) & ~0x8000000000000000UL)
#endif

#ifndef f64_neg
#define f64_neg(u)        ((uint64_t) (u) ^ 0x8000000000000000UL)
#endif





extern THREAD_LOCAL uint_fast8_t extF80_roundingPrecision;




#ifdef SOFTFLOAT_FAST_INT64
uint_fast32_t extF80_to_ui32( extFloat80_t, uint_fast8_t, bool );
uint_fast64_t extF80_to_ui64( extFloat80_t, uint_fast8_t, bool );
int_fast32_t extF80_to_i32( extFloat80_t, uint_fast8_t, bool );
int_fast64_t extF80_to_i64( extFloat80_t, uint_fast8_t, bool );
uint_fast32_t extF80_to_ui32_r_minMag( extFloat80_t, bool );
uint_fast64_t extF80_to_ui64_r_minMag( extFloat80_t, bool );
int_fast32_t extF80_to_i32_r_minMag( extFloat80_t, bool );
int_fast64_t extF80_to_i64_r_minMag( extFloat80_t, bool );
float16_t extF80_to_f16( extFloat80_t );
float32_t extF80_to_f32( extFloat80_t );
float64_t extF80_to_f64( extFloat80_t );
float128_t extF80_to_f128( extFloat80_t );
extFloat80_t extF80_roundToInt( extFloat80_t, uint_fast8_t, bool );
extFloat80_t extF80_add( extFloat80_t, extFloat80_t );
extFloat80_t extF80_sub( extFloat80_t, extFloat80_t );
extFloat80_t extF80_mul( extFloat80_t, extFloat80_t );
extFloat80_t extF80_div( extFloat80_t, extFloat80_t );
extFloat80_t extF80_rem( extFloat80_t, extFloat80_t );
extFloat80_t extF80_sqrt( extFloat80_t );
bool extF80_eq( extFloat80_t, extFloat80_t );
bool extF80_le( extFloat80_t, extFloat80_t );
bool extF80_lt( extFloat80_t, extFloat80_t );
bool extF80_eq_signaling( extFloat80_t, extFloat80_t );
bool extF80_le_quiet( extFloat80_t, extFloat80_t );
bool extF80_lt_quiet( extFloat80_t, extFloat80_t );
bool extF80_isSignalingNaN( extFloat80_t );
#endif
uint_fast32_t extF80M_to_ui32( const extFloat80_t *, uint_fast8_t, bool );
uint_fast64_t extF80M_to_ui64( const extFloat80_t *, uint_fast8_t, bool );
int_fast32_t extF80M_to_i32( const extFloat80_t *, uint_fast8_t, bool );
int_fast64_t extF80M_to_i64( const extFloat80_t *, uint_fast8_t, bool );
uint_fast32_t extF80M_to_ui32_r_minMag( const extFloat80_t *, bool );
uint_fast64_t extF80M_to_ui64_r_minMag( const extFloat80_t *, bool );
int_fast32_t extF80M_to_i32_r_minMag( const extFloat80_t *, bool );
int_fast64_t extF80M_to_i64_r_minMag( const extFloat80_t *, bool );
float16_t extF80M_to_f16( const extFloat80_t * );
float32_t extF80M_to_f32( const extFloat80_t * );
float64_t extF80M_to_f64( const extFloat80_t * );
void extF80M_to_f128M( const extFloat80_t *, float128_t * );
void
 extF80M_roundToInt(
     const extFloat80_t *, uint_fast8_t, bool, extFloat80_t * );
void extF80M_add( const extFloat80_t *, const extFloat80_t *, extFloat80_t * );
void extF80M_sub( const extFloat80_t *, const extFloat80_t *, extFloat80_t * );
void extF80M_mul( const extFloat80_t *, const extFloat80_t *, extFloat80_t * );
void extF80M_div( const extFloat80_t *, const extFloat80_t *, extFloat80_t * );
void extF80M_rem( const extFloat80_t *, const extFloat80_t *, extFloat80_t * );
void extF80M_sqrt( const extFloat80_t *, extFloat80_t * );
bool extF80M_eq( const extFloat80_t *, const extFloat80_t * );
bool extF80M_le( const extFloat80_t *, const extFloat80_t * );
bool extF80M_lt( const extFloat80_t *, const extFloat80_t * );
bool extF80M_eq_signaling( const extFloat80_t *, const extFloat80_t * );
bool extF80M_le_quiet( const extFloat80_t *, const extFloat80_t * );
bool extF80M_lt_quiet( const extFloat80_t *, const extFloat80_t * );
bool extF80M_isSignalingNaN( const extFloat80_t * );




#ifdef SOFTFLOAT_FAST_INT64
uint_fast32_t f128_to_ui32( float128_t, uint_fast8_t, bool );
uint_fast64_t f128_to_ui64( float128_t, uint_fast8_t, bool );
int_fast32_t f128_to_i32( float128_t, uint_fast8_t, bool );
int_fast64_t f128_to_i64( float128_t, uint_fast8_t, bool );
uint_fast32_t f128_to_ui32_r_minMag( float128_t, bool );
uint_fast64_t f128_to_ui64_r_minMag( float128_t, bool );
int_fast32_t f128_to_i32_r_minMag( float128_t, bool );
int_fast64_t f128_to_i64_r_minMag( float128_t, bool );
float16_t f128_to_f16( float128_t );
float32_t f128_to_f32( float128_t );
float64_t f128_to_f64( float128_t );
extFloat80_t f128_to_extF80( float128_t );
float128_t f128_roundToInt( float128_t, uint_fast8_t, bool );
float128_t f128_add( float128_t, float128_t );
float128_t f128_sub( float128_t, float128_t );
float128_t f128_mul( float128_t, float128_t );
float128_t f128_mulAdd( float128_t, float128_t, float128_t );
float128_t f128_div( float128_t, float128_t );
float128_t f128_rem( float128_t, float128_t );
float128_t f128_sqrt( float128_t );
bool f128_eq( float128_t, float128_t );
bool f128_le( float128_t, float128_t );
bool f128_lt( float128_t, float128_t );
bool f128_eq_signaling( float128_t, float128_t );
bool f128_le_quiet( float128_t, float128_t );
bool f128_lt_quiet( float128_t, float128_t );
bool f128_isSignalingNaN( float128_t );
#endif
uint_fast32_t f128M_to_ui32( const float128_t *, uint_fast8_t, bool );
uint_fast64_t f128M_to_ui64( const float128_t *, uint_fast8_t, bool );
int_fast32_t f128M_to_i32( const float128_t *, uint_fast8_t, bool );
int_fast64_t f128M_to_i64( const float128_t *, uint_fast8_t, bool );
uint_fast32_t f128M_to_ui32_r_minMag( const float128_t *, bool );
uint_fast64_t f128M_to_ui64_r_minMag( const float128_t *, bool );
int_fast32_t f128M_to_i32_r_minMag( const float128_t *, bool );
int_fast64_t f128M_to_i64_r_minMag( const float128_t *, bool );
float16_t f128M_to_f16( const float128_t * );
float32_t f128M_to_f32( const float128_t * );
float64_t f128M_to_f64( const float128_t * );
void f128M_to_extF80M( const float128_t *, extFloat80_t * );
void f128M_roundToInt( const float128_t *, uint_fast8_t, bool, float128_t * );
void f128M_add( const float128_t *, const float128_t *, float128_t * );
void f128M_sub( const float128_t *, const float128_t *, float128_t * );
void f128M_mul( const float128_t *, const float128_t *, float128_t * );
void
 f128M_mulAdd(
     const float128_t *, const float128_t *, const float128_t *, float128_t *
 );
void f128M_div( const float128_t *, const float128_t *, float128_t * );
void f128M_rem( const float128_t *, const float128_t *, float128_t * );
void f128M_sqrt( const float128_t *, float128_t * );
bool f128M_eq( const float128_t *, const float128_t * );
bool f128M_le( const float128_t *, const float128_t * );
bool f128M_lt( const float128_t *, const float128_t * );
bool f128M_eq_signaling( const float128_t *, const float128_t * );
bool f128M_le_quiet( const float128_t *, const float128_t * );
bool f128M_lt_quiet( const float128_t *, const float128_t * );
bool f128M_isSignalingNaN( const float128_t * );

#endif