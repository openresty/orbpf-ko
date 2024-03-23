/* Copyright (C) by OpenResty Inc. All rights reserved. */



































#ifndef softfloat_types_h
#define softfloat_types_h 1










typedef struct { uint16_t v; } float16_t;
typedef struct { uint32_t v; } float32_t;
typedef struct { uint64_t v; } float64_t;
typedef struct { uint64_t v[2]; } float128_t;






#ifdef LITTLEENDIAN
struct extFloat80M { uint64_t signif; uint16_t signExp; };
#else
struct extFloat80M { uint16_t signExp; uint64_t signif; };
#endif













typedef struct extFloat80M extFloat80_t;

#endif