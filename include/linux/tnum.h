/* Copyright (C) by OpenResty Inc. All rights reserved. */







#ifndef _ORBPF_LINUX_TNUM_H
#define _ORBPF_LINUX_TNUM_H

#include <linux/types.h>

struct tnum {
	u64 value;
	u64 mask;
};

 
 
struct tnum tnum_const(u64 value);
 
extern const struct tnum tnum_unknown;
 
struct tnum tnum_range(u64 min, u64 max);

 
 
struct tnum tnum_lshift(struct tnum a, u8 shift);
 
struct tnum tnum_rshift(struct tnum a, u8 shift);
 
struct tnum tnum_arshift(struct tnum a, u8 min_shift, u8 insn_bitness);
 
struct tnum tnum_add(struct tnum a, struct tnum b);
 
struct tnum tnum_sub(struct tnum a, struct tnum b);
 
struct tnum tnum_and(struct tnum a, struct tnum b);
 
struct tnum tnum_or(struct tnum a, struct tnum b);
 
struct tnum tnum_xor(struct tnum a, struct tnum b);
 
struct tnum tnum_mul(struct tnum a, struct tnum b);

 
struct tnum tnum_intersect(struct tnum a, struct tnum b);

 
struct tnum tnum_cast(struct tnum a, u8 size);

 
static inline bool tnum_is_const(struct tnum a)
{
	return !a.mask;
}

 
static inline bool tnum_equals_const(struct tnum a, u64 b)
{
	return tnum_is_const(a) && a.value == b;
}

 
static inline bool tnum_is_unknown(struct tnum a)
{
	return !~a.mask;
}




bool tnum_is_aligned(struct tnum a, u64 size);

 
bool tnum_in(struct tnum a, struct tnum b);






 
int tnum_strn(char *str, size_t size, struct tnum a);
 
int tnum_sbin(char *str, size_t size, struct tnum a);

 
struct tnum tnum_subreg(struct tnum a);
 
struct tnum tnum_clear_subreg(struct tnum a);
 
struct tnum tnum_const_subreg(struct tnum a, u32 value);
 
static inline bool tnum_subreg_is_const(struct tnum a)
{
	return !(tnum_subreg(a)).mask;
}

#endif  