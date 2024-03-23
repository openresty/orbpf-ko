/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
 

#include <linux/ctype.h>

static noinline_for_stack
int skip_atoi(const char **s)
{
	int i = 0;

	do {
		i = i*10 + *((*s)++) - '0';
	} while (isdigit(**s));

	return i;
}


























static const u16 decpair[100] = {
#define _(x) (__force u16) cpu_to_le16(((x % 10) | ((x / 10) << 8)) + 0x3030)
	_( 0), _( 1), _( 2), _( 3), _( 4), _( 5), _( 6), _( 7), _( 8), _( 9),
	_(10), _(11), _(12), _(13), _(14), _(15), _(16), _(17), _(18), _(19),
	_(20), _(21), _(22), _(23), _(24), _(25), _(26), _(27), _(28), _(29),
	_(30), _(31), _(32), _(33), _(34), _(35), _(36), _(37), _(38), _(39),
	_(40), _(41), _(42), _(43), _(44), _(45), _(46), _(47), _(48), _(49),
	_(50), _(51), _(52), _(53), _(54), _(55), _(56), _(57), _(58), _(59),
	_(60), _(61), _(62), _(63), _(64), _(65), _(66), _(67), _(68), _(69),
	_(70), _(71), _(72), _(73), _(74), _(75), _(76), _(77), _(78), _(79),
	_(80), _(81), _(82), _(83), _(84), _(85), _(86), _(87), _(88), _(89),
	_(90), _(91), _(92), _(93), _(94), _(95), _(96), _(97), _(98), _(99),
#undef _
};







static noinline_for_stack
char *put_dec_trunc8(char *buf, unsigned r)
{
	unsigned q;

	 
	if (r < 100)
		goto out_r;

	 
	q = (r * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	 
	if (q < 100)
		goto out_q;

	 
	r = (q * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[q - 100*r];
	buf += 2;

	 
	if (r < 100)
		goto out_r;

	 
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;
out_q:
	 
	r = q;
out_r:
	 
	*((u16 *)buf) = decpair[r];
	buf += r < 10 ? 1 : 2;
	return buf;
}

static noinline_for_stack
char *put_dec_full8(char *buf, unsigned r)
{
	unsigned q;

	 
	q = (r * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	 
	r = (q * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[q - 100*r];
	buf += 2;

	 
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	 
	*((u16 *)buf) = decpair[q];
	buf += 2;
	return buf;
}

static noinline_for_stack
char *put_dec(char *buf, unsigned long long n)
{
	if (n >= 100*1000*1000)
		buf = put_dec_full8(buf, do_div(n, 100*1000*1000));
	 
	if (n >= 100*1000*1000)
		buf = put_dec_full8(buf, do_div(n, 100*1000*1000));
	 
	return put_dec_trunc8(buf, n);
}

#define SIGN	1		 
#define LEFT	2		 
#define PLUS	4		 
#define SPACE	8		 
#define ZEROPAD	16		 
#define SMALL	32		 
#define SPECIAL	64		 

static_assert(ZEROPAD == ('0' - ' '));
static_assert(SMALL == ' ');

enum format_type {
	FORMAT_TYPE_NONE,  
	FORMAT_TYPE_WIDTH,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_PTR,
	FORMAT_TYPE_PERCENT_CHAR,
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_LONG_LONG,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
	FORMAT_TYPE_SIZE_T,
	FORMAT_TYPE_PTRDIFF,
	FORMAT_TYPE_FLOAT,
};

struct printf_spec {
	unsigned int	type:8;		 
	signed int	field_width:24;	 
	unsigned int	flags:8;	 
	unsigned int	base:8;		 
	signed int	precision:16;	 
} __packed;
static_assert(sizeof(struct printf_spec) == 8);

#define FIELD_WIDTH_MAX ((1 << 23) - 1)
#define PRECISION_MAX ((1 << 15) - 1)

static noinline_for_stack
char *number(char *buf, char *end, unsigned long long num,
	     struct printf_spec spec)
{
	 
	char tmp[3 * sizeof(num)] __aligned(2);
	char sign;
	char locase;
	int need_pfx = ((spec.flags & SPECIAL) && spec.base != 10);
	int i;
	bool is_zero = num == 0LL;
	int field_width = spec.field_width;
	int precision = spec.precision;

	

	locase = (spec.flags & SMALL);
	if (spec.flags & LEFT)
		spec.flags &= ~ZEROPAD;
	sign = 0;
	if (spec.flags & SIGN) {
		if ((signed long long)num < 0) {
			sign = '-';
			num = -(signed long long)num;
			field_width--;
		} else if (spec.flags & PLUS) {
			sign = '+';
			field_width--;
		} else if (spec.flags & SPACE) {
			sign = ' ';
			field_width--;
		}
	}
	if (need_pfx) {
		if (spec.base == 16)
			field_width -= 2;
		else if (!is_zero)
			field_width--;
	}

	 
	i = 0;
	if (num < spec.base)
		tmp[i++] = hex_asc_upper[num] | locase;
	else if (spec.base != 10) {  
		int mask = spec.base - 1;
		int shift = 3;

		if (spec.base == 16)
			shift = 4;
		do {
			tmp[i++] = (hex_asc_upper[((unsigned char)num) & mask] | locase);
			num >>= shift;
		} while (num);
	} else {  
		i = put_dec(tmp, num) - tmp;
	}

	 
	if (i > precision)
		precision = i;
	 
	field_width -= precision;
	if (!(spec.flags & (ZEROPAD | LEFT))) {
		while (--field_width >= 0) {
			if (buf < end)
				*buf = ' ';
			++buf;
		}
	}
	 
	if (sign) {
		if (buf < end)
			*buf = sign;
		++buf;
	}
	 
	if (need_pfx) {
		if (spec.base == 16 || !is_zero) {
			if (buf < end)
				*buf = '0';
			++buf;
		}
		if (spec.base == 16) {
			if (buf < end)
				*buf = ('X' | locase);
			++buf;
		}
	}
	 
	if (!(spec.flags & LEFT)) {
		char c = ' ' + (spec.flags & ZEROPAD);

		while (--field_width >= 0) {
			if (buf < end)
				*buf = c;
			++buf;
		}
	}
	 
	while (i <= --precision) {
		if (buf < end)
			*buf = '0';
		++buf;
	}
	 
	while (--i >= 0) {
		if (buf < end)
			*buf = tmp[i];
		++buf;
	}
	 
	while (--field_width >= 0) {
		if (buf < end)
			*buf = ' ';
		++buf;
	}

	return buf;
}

#pragma GCC diagnostic ignored "-Wunused-function"
#include "softfpu/platform.h"
#include "softfpu/primitives.h"
#include "softfpu/specialize.h"

#include "softfpu/softfloat_raiseFlags.c"

#include "softfpu/s_addMagsF64.c"
#include "softfpu/s_mul64To128M.c"
#include "softfpu/s_mul64To128M.c"
#include "softfpu/s_normRoundPackToF64.c"
#include "softfpu/s_normSubnormalF64Sig.c"
#include "softfpu/s_propagateNaNF64UI.c"
#include "softfpu/s_roundMToUI64.c"
#include "softfpu/s_roundPackToF64.c"
#include "softfpu/s_shiftRightJam64.c"
#include "softfpu/s_shiftRightJam64.c"
#include "softfpu/s_shiftRightJamM.c"
#include "softfpu/s_shortShiftRightJam64.c"
#include "softfpu/s_shortShiftRightJamM.c"
#include "softfpu/s_subMagsF64.c"

#include "softfpu/f64_to_ui64_r_minMag.c"
#include "softfpu/f64_to_ui64.c"
#include "softfpu/ui64_to_f64.c"
#include "softfpu/f64_sub.c"
#include "softfpu/f64_mul.c"

#define NAN_literal          "nan"
#define INFINITY_literal     "inf"

#define isnan(u)        ((((u) & UINT64_C(0x7FF0000000000000)) == UINT64_C(0x7FF0000000000000)) \
                         && ((u) & UINT64_C(0xFFFFFFFFFFFFF)))

#define isinf(u)        ((((u) & UINT64_C(0x7FF0000000000000)) == UINT64_C(0x7FF0000000000000)) \
                         && ((u) & UINT64_C(0xFFFFFFFFFFFFF)) == 0)

noinline static char *
double_number(char * buf, char * end, uint64_t num,
	     struct printf_spec spec)
{
	float64_t f, scalef;
	uint64_t u, frac, scale = 1, i;
	int precision;

	f.v = num;

	if (isnan(num)) {
		memcpy(buf, NAN_literal, sizeof(NAN_literal) - 1);

		return buf + (sizeof(NAN_literal) - 1);
	}

	if (f64_isneg(num)) {
		f.v = f64_abs(num);

		if (buf <= end)
			*buf = '-';
		++buf;
	}

	if (isinf(num)) {
		memcpy(buf, INFINITY_literal, sizeof(INFINITY_literal) - 1);

		return buf + (sizeof(INFINITY_literal) - 1);
	}

	u = f64_to_ui64_r_minMag(f, false);
	frac = 0;

	if (spec.precision == -1)
		spec.precision = 6;

	if (spec.precision >= 0) {
		for (i = spec.precision; i; i--) {
			scale *= 10;
		}

		scalef = ui64_to_f64(scale);

		frac = f64_to_ui64(
				f64_mul(
					f64_sub(f, ui64_to_f64(u)),
					scalef),
				softfloat_round_near_even,
				false);

		if (frac == scale) {
			u++;
			frac = 0;
		}
	}


	precision = spec.precision;
	spec.precision = -1;
	buf = number(buf, end, u, spec);
	spec.precision = precision;

	if (spec.precision >= 0) {
		if (buf <= end)
			*buf = '.';
		++buf;

		buf = number(buf, end, frac, spec);
	}

	return buf;
}

static void move_right(char *buf, char *end, unsigned len, unsigned spaces)
{
	size_t size;
	if (buf >= end)	 
		return;
	size = end - buf;
	if (size <= spaces) {
		memset(buf, ' ', size);
		return;
	}
	if (len) {
		if (len > size - spaces)
			len = size - spaces;
		memmove(buf + spaces, buf, len);
	}
	memset(buf, ' ', spaces);
}









static noinline_for_stack
char *widen_string(char *buf, int n, char *end, struct printf_spec spec)
{
	unsigned spaces;

	if (likely(n >= spec.field_width))
		return buf;
	 
	spaces = spec.field_width - n;
	if (!(spec.flags & LEFT)) {
		move_right(buf - n, end, n, spaces);
		return buf + spaces;
	}
	while (spaces--) {
		if (buf < end)
			*buf = ' ';
		++buf;
	}
	return buf;
}

 
static char *string_nocheck(char *buf, char *end, const char *s,
			    struct printf_spec spec)
{
	int len = 0;
	int lim = spec.precision;

	while (lim--) {
		char c = *s++;
		if (!c)
			break;
		if (buf < end)
			*buf = c;
		++buf;
		++len;
	}
	return widen_string(buf, len, end, spec);
}

static char *err_ptr(char *buf, char *end, void *ptr,
		     struct printf_spec spec)
{
	int err = PTR_ERR(ptr);

	




	spec.flags |= SIGN;
	spec.base = 10;
	return number(buf, end, err, spec);
}

 
static char *error_string(char *buf, char *end, const char *s,
			  struct printf_spec spec)
{
	




	if (spec.precision == -1)
		spec.precision = 2 * sizeof(void *);

	return string_nocheck(buf, end, s, spec);
}






static const char *check_pointer_msg(const void *ptr)
{
	if (!ptr)
		return "(null)";

	if ((unsigned long)ptr < PAGE_SIZE || IS_ERR_VALUE(ptr))
		return "(efault)";

	return NULL;
}

static int check_pointer(char **buf, char *end, const void *ptr,
			 struct printf_spec spec)
{
	const char *err_msg;

	err_msg = check_pointer_msg(ptr);
	if (err_msg) {
		*buf = error_string(*buf, end, err_msg, spec);
		return -EFAULT;
	}

	return 0;
}

static noinline_for_stack
char *string(char *buf, char *end, const char *s,
	     struct printf_spec spec)
{
	if (check_pointer(&buf, end, s, spec))
		return buf;

	return string_nocheck(buf, end, s, spec);
}

static char *pointer_string(char *buf, char *end,
			    const void *ptr,
			    struct printf_spec spec)
{
	spec.base = 16;
	spec.flags |= SMALL;
	if (spec.field_width == -1) {
		spec.field_width = 2 * sizeof(ptr);
		spec.flags |= ZEROPAD;
	}

	return number(buf, end, (unsigned long int)ptr, spec);
}

static noinline_for_stack
char *symbol_string(char *buf, char *end, void *ptr,
		    struct printf_spec spec, const char *fmt)
{
	unsigned long value;
	char sym[KSYM_SYMBOL_LEN];

	if (fmt[1] == 'R')
		ptr = __builtin_extract_return_addr(ptr);
	value = (unsigned long)ptr;

	if (*fmt == 'B')
		sprint_backtrace(sym, value);
	else if (*fmt != 's')
		sprint_symbol(sym, value);
	else
		sprint_symbol_no_offset(sym, value);

	return string_nocheck(buf, end, sym, spec);
}

 
static noinline_for_stack
char *pointer(const char *fmt, char *buf, char *end, void *ptr,
	      struct printf_spec spec)
{
	switch (*fmt) {
	case 'S':
	case 's':
#ifdef ORBPF_CONF_DEREFERENCE_SYMBOL_DESCRIPTOR
		ptr = dereference_symbol_descriptor(ptr);
#endif
		return symbol_string(buf, end, ptr, spec, fmt);
	case 'e':
		 
		if (!IS_ERR(ptr))
			break;
		return err_ptr(buf, end, ptr, spec);
	}

	return pointer_string(buf, end, ptr, spec);
}






















static noinline_for_stack
int format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;
	char qualifier;

	 
	if (spec->type == FORMAT_TYPE_WIDTH) {
		if (spec->field_width < 0) {
			spec->field_width = -spec->field_width;
			spec->flags |= LEFT;
		}
		spec->type = FORMAT_TYPE_NONE;
		goto precision;
	}

	 
	if (spec->type == FORMAT_TYPE_PRECISION) {
		if (spec->precision < 0)
			spec->precision = 0;

		spec->type = FORMAT_TYPE_NONE;
		goto qualifier;
	}

	 
	spec->type = FORMAT_TYPE_NONE;

	for (; *fmt ; ++fmt) {
		if (*fmt == '%')
			break;
	}

	 
	if (fmt != start || !*fmt)
		return fmt - start;

	 
	spec->flags = 0;

	while (1) {  
		bool found = true;

		++fmt;

		switch (*fmt) {
		case '-': spec->flags |= LEFT;    break;
		case '+': spec->flags |= PLUS;    break;
		case ' ': spec->flags |= SPACE;   break;
		case '#': spec->flags |= SPECIAL; break;
		case '0': spec->flags |= ZEROPAD; break;
		default:  found = false;
		}

		if (!found)
			break;
	}

	 
	spec->field_width = -1;

	if (isdigit(*fmt))
		spec->field_width = skip_atoi(&fmt);
	else if (*fmt == '*') {
		 
		spec->type = FORMAT_TYPE_WIDTH;
		return ++fmt - start;
	}

precision:
	 
	spec->precision = -1;
	if (*fmt == '.') {
		++fmt;
		if (isdigit(*fmt)) {
			spec->precision = skip_atoi(&fmt);
			if (spec->precision < 0)
				spec->precision = 0;
		} else if (*fmt == '*') {
			 
			spec->type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

qualifier:
	 
	qualifier = 0;
	if (*fmt == 'h' || _tolower(*fmt) == 'l' ||
	    *fmt == 'z' || *fmt == 't') {
		qualifier = *fmt++;
		if (unlikely(qualifier == *fmt)) {
			if (qualifier == 'l') {
				qualifier = 'L';
				++fmt;
			} else if (qualifier == 'h') {
				qualifier = 'H';
				++fmt;
			}
		}
	}

	 
	spec->base = 10;
	switch (*fmt) {
	case 'c':
		spec->type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		spec->type = FORMAT_TYPE_STR;
		return ++fmt - start;

	case 'p':
		spec->type = FORMAT_TYPE_PTR;
		return ++fmt - start;

	case '%':
		spec->type = FORMAT_TYPE_PERCENT_CHAR;
		return ++fmt - start;

	case 'f':
		spec->type = FORMAT_TYPE_FLOAT;
		return ++fmt - start;

	 
	case 'o':
		spec->base = 8;
		break;

	case 'x':
		spec->flags |= SMALL;
		fallthrough;

	case 'X':
		spec->base = 16;
		break;

	case 'd':
	case 'i':
		spec->flags |= SIGN;
		break;
	case 'u':
		break;

	case 'n':
		




		fallthrough;

	default:
		WARN_ONCE(1, "Please remove unsupported %%%c in format string\n", *fmt);
		spec->type = FORMAT_TYPE_INVALID;
		return fmt - start;
	}

	if (qualifier == 'L')
		spec->type = FORMAT_TYPE_LONG_LONG;
	else if (qualifier == 'l') {
		BUILD_BUG_ON(FORMAT_TYPE_ULONG + SIGN != FORMAT_TYPE_LONG);
		spec->type = FORMAT_TYPE_ULONG + (spec->flags & SIGN);
	} else if (qualifier == 'z') {
		spec->type = FORMAT_TYPE_SIZE_T;
	} else if (qualifier == 't') {
		spec->type = FORMAT_TYPE_PTRDIFF;
	} else if (qualifier == 'H') {
		BUILD_BUG_ON(FORMAT_TYPE_UBYTE + SIGN != FORMAT_TYPE_BYTE);
		spec->type = FORMAT_TYPE_UBYTE + (spec->flags & SIGN);
	} else if (qualifier == 'h') {
		BUILD_BUG_ON(FORMAT_TYPE_USHORT + SIGN != FORMAT_TYPE_SHORT);
		spec->type = FORMAT_TYPE_USHORT + (spec->flags & SIGN);
	} else {
		BUILD_BUG_ON(FORMAT_TYPE_UINT + SIGN != FORMAT_TYPE_INT);
		spec->type = FORMAT_TYPE_UINT + (spec->flags & SIGN);
	}

	return ++fmt - start;
}

static void
set_field_width(struct printf_spec *spec, int width)
{
	spec->field_width = width;
	if (WARN_ONCE(spec->field_width != width, "field width %d too large", width)) {
		spec->field_width = clamp(width, -FIELD_WIDTH_MAX, FIELD_WIDTH_MAX);
	}
}

static void
set_precision(struct printf_spec *spec, int prec)
{
	spec->precision = prec;
	if (WARN_ONCE(spec->precision != prec, "precision %d too large", prec)) {
		spec->precision = clamp(prec, 0, PRECISION_MAX);
	}
}























int bstr_printf(char *buf, size_t size, const char *fmt, const u32 *bin_buf)
{
	struct printf_spec spec = {0};
	char *str, *end;
	const char *args = (const char *)bin_buf;

	if (WARN_ON_ONCE(size > INT_MAX))
		return 0;

	str = buf;
	end = buf + size;

#define get_arg(type)							\
({									\
	typeof(type) value;						\
	if (sizeof(type) == 8) {					\
		args = PTR_ALIGN(args, sizeof(u32));			\
		*(u32 *)&value = *(u32 *)args;				\
		*((u32 *)&value + 1) = *(u32 *)(args + 4);		\
	} else {							\
		args = PTR_ALIGN(args, sizeof(type));			\
		value = *(typeof(type) *)args;				\
	}								\
	args += sizeof(type);						\
	value;								\
})

	 
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);

		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE: {
			int copy = read;
			if (str < end) {
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			break;
		}

		case FORMAT_TYPE_WIDTH:
			set_field_width(&spec, get_arg(int));
			break;

		case FORMAT_TYPE_PRECISION:
			set_precision(&spec, get_arg(int));
			break;

		case FORMAT_TYPE_CHAR: {
			char c;

			if (!(spec.flags & LEFT)) {
				while (--spec.field_width > 0) {
					if (str < end)
						*str = ' ';
					++str;
				}
			}
			c = (unsigned char) get_arg(char);
			if (str < end)
				*str = c;
			++str;
			while (--spec.field_width > 0) {
				if (str < end)
					*str = ' ';
				++str;
			}
			break;
		}

		case FORMAT_TYPE_STR: {
			const char *str_arg = args;
			args += strlen(str_arg) + 1;
			str = string(str, end, (char *)str_arg, spec);
			break;
		}

		case FORMAT_TYPE_PTR: {
			bool process = false;
			int copy, len;
			 
			switch (*fmt) {
			case 'S':
			case 's':
			case 'x':
			case 'K':
			case 'e':
				process = true;
				break;
			default:
				if (!isalnum(*fmt)) {
					process = true;
					break;
				}
				 
				if (str < end) {
					len = copy = strlen(args);
					if (copy > end - str)
						copy = end - str;
					memcpy(str, args, copy);
					str += len;
					args += len + 1;
				}
			}
			if (process)
				str = pointer(fmt, str, end, get_arg(void *), spec);

			while (isalnum(*fmt))
				fmt++;
			break;
		}

		case FORMAT_TYPE_PERCENT_CHAR:
			if (str < end)
				*str = '%';
			++str;
			break;

		case FORMAT_TYPE_FLOAT: {
			uint64_t num;
			num = get_arg(uint64_t);
			str = double_number(str, end, num, spec);
			break;
		}
		case FORMAT_TYPE_INVALID:
			goto out;

		default: {
			unsigned long long num;

			switch (spec.type) {

			case FORMAT_TYPE_LONG_LONG:
				num = get_arg(long long);
				break;
			case FORMAT_TYPE_ULONG:
			case FORMAT_TYPE_LONG:
				num = get_arg(unsigned long);
				break;
			case FORMAT_TYPE_SIZE_T:
				num = get_arg(size_t);
				break;
			case FORMAT_TYPE_PTRDIFF:
				num = get_arg(ptrdiff_t);
				break;
			case FORMAT_TYPE_UBYTE:
				num = get_arg(unsigned char);
				break;
			case FORMAT_TYPE_BYTE:
				num = get_arg(signed char);
				break;
			case FORMAT_TYPE_USHORT:
				num = get_arg(unsigned short);
				break;
			case FORMAT_TYPE_SHORT:
				num = get_arg(short);
				break;
			case FORMAT_TYPE_UINT:
				num = get_arg(unsigned int);
				break;
			default:
				num = get_arg(int);
			}

			str = number(str, end, num, spec);
		}  
		}  
	}  

out:
	if (size > 0) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}

#undef get_arg

	 
	return str - buf;
}