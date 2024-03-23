/* Copyright (C) by OpenResty Inc. All rights reserved. */


#include <linux/bpf.h>
#include <linux/rcupdate.h>
#include <linux/random.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/filter.h>
#include <linux/ctype.h>
#include <linux/jiffies.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/security.h>
#include <asm/timex.h>

#pragma GCC diagnostic ignored "-Wunused-function"
#include "softfpu/platform.h"
#include "softfpu/opts-GCC.h"
#include "softfpu/primitives.h"
#include "softfpu/specialize.h"

#include "softfpu/softfloat_raiseFlags.c"
#include "softfpu/softfloat_state.c"

#include "softfpu/s_f32UIToCommonNaN.c"
#include "softfpu/s_normSubnormalF32Sig.c"
#include "softfpu/s_normSubnormalF64Sig.c"
#include "softfpu/s_commonNaNToF64UI.c"
#include "softfpu/s_approxRecipSqrt32_1.c"
#include "softfpu/s_approxRecipSqrt_1Ks.c"
#include "softfpu/s_subMagsF32.c"
#include "softfpu/s_subMagsF64.c"
#include "softfpu/s_addMagsF32.c"
#include "softfpu/s_addMagsF64.c"
#include "softfpu/s_propagateNaNF32UI.c"
#include "softfpu/s_propagateNaNF64UI.c"
#include "softfpu/s_mul64To128M.c"

#include "softfpu/s_f64UIToCommonNaN.c"
#include "softfpu/s_commonNaNToF32UI.c"
#include "softfpu/s_roundPackToF32.c"
#include "softfpu/s_roundPackToF64.c"
#include "softfpu/s_shiftRightJam32.c"
#include "softfpu/s_shiftRightJam64.c"
#include "softfpu/s_shortShiftRightJam64.c"
#include "softfpu/s_normRoundPackToF32.c"
#include "softfpu/s_normRoundPackToF64.c"
#include "softfpu/s_approxRecip32_1.c"
#include "softfpu/s_approxRecip_1Ks.c"

#include "softfpu/i64_to_f64.c"
#include "softfpu/ui64_to_f64.c"
#include "softfpu/i32_to_f64.c"
#include "softfpu/ui32_to_f64.c"

#include "softfpu/f64_to_i32_r_minMag.c"
#include "softfpu/f64_to_ui32_r_minMag.c"

#include "softfpu/f64_to_i64_r_minMag.c"
#include "softfpu/f64_to_ui64_r_minMag.c"

#include "softfpu/f32_to_f64.c"
#include "softfpu/f64_to_f32.c"

#include "softfpu/f32_to_i32_r_minMag.c"
#include "softfpu/f32_to_ui32_r_minMag.c"

#include "softfpu/f32_to_i64_r_minMag.c"
#include "softfpu/f32_to_ui64_r_minMag.c"

#include "softfpu/i32_to_f32.c"
#include "softfpu/ui32_to_f32.c"

#include "softfpu/i64_to_f32.c"
#include "softfpu/ui64_to_f32.c"

#include "softfpu/f64_add.c"
#include "softfpu/f64_sub.c"
#include "softfpu/f64_mul.c"
#include "softfpu/f64_div.c"

#include "softfpu/f64_rem.c"
#include "softfpu/f64_sqrt.c"
#include "softfpu/f64_roundToInt.c"

#include "softfpu/f64_le_quiet.c"
#include "softfpu/f64_lt_quiet.c"
#include "softfpu/f64_eq.c"

#include "softfpu/f32_add.c"
#include "softfpu/f32_sub.c"
#include "softfpu/f32_mul.c"
#include "softfpu/f32_div.c"

#include "softfpu/f32_rem.c"
#include "softfpu/f32_sqrt.c"
#include "softfpu/f32_roundToInt.c"

#include "softfpu/f32_le_quiet.c"
#include "softfpu/f32_lt_quiet.c"
#include "softfpu/f32_eq.c"
#include <linux/orbpf_config_begin.h>  

static struct bpf_stat_data __percpu *pcpu_sd_init_val; static s64  __percpu *pcpu_agg_histogram; static unsigned long __percpu *irqsave_flags; static struct bpf_bprintf_buffers __percpu *bpf_bprintf_bufs; static int __percpu *bpf_bprintf_nest_level;

 
#define KSTRTOX_OVERFLOW	(1U << 31)
const char *_parse_integer_fixup_radix(const char *s, unsigned int *base);
unsigned int _parse_integer(const char *s, unsigned int base, unsigned long long *res);










BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return (unsigned long) map->ops->map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
	   void *, value, u64, flags)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_update_elem(map, key, value, flags);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
	.func		= bpf_map_update_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_delete_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_delete_elem(map, key);
}

const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.func		= bpf_map_delete_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_1(bpf_map_clear, struct bpf_map *, map)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return bpf_map_clear_fn(map->ops)(map);
}

const struct bpf_func_proto bpf_map_clear_proto = {
	.func		= bpf_map_clear,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
};

BPF_CALL_3(bpf_map_push_elem, struct bpf_map *, map, void *, value, u64, flags)
{
	return map->ops->map_push_elem(map, value, flags);
}

const struct bpf_func_proto bpf_map_push_elem_proto = {
	.func		= bpf_map_push_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_pop_elem, struct bpf_map *, map, void *, value)
{
	return map->ops->map_pop_elem(map, value);
}

const struct bpf_func_proto bpf_map_pop_elem_proto = {
	.func		= bpf_map_pop_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
};

BPF_CALL_2(bpf_map_peek_elem, struct bpf_map *, map, void *, value)
{
	return map->ops->map_peek_elem(map, value);
}

const struct bpf_func_proto bpf_map_peek_elem_proto = {
	.func		= bpf_map_peek_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
};

BPF_CALL_3(bpf_map_get_next_key, struct bpf_map *, map, void *, key,
	   void *, next_key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_get_next_key(map, key, next_key);
}

const struct bpf_func_proto bpf_map_get_next_key_proto = {
	.func		= bpf_map_get_next_key,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_hash_map_sort, struct bpf_map *, map, void *, key,
	   void *, next_key, void *, cmp_fn, void *, priv)
{
	return bpf_hash_sort_next_key(map, key, next_key, cmp_fn, priv);
}

const struct bpf_func_proto bpf_hash_map_sort_proto = {
	.func		= bpf_hash_map_sort,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_PTR_TO_FUNC,
	.arg5_type	= ARG_ANYTHING  ,
};

#define HIST_WIDTH 50
#define HIST_ELISION 2  
#define HIST_LOG_BUCKETS 128
#define HIST_LOG_BUCKET0 64

static int hist_linear_calc_buckets(struct bpf_hist_data *st)
{
	if (st->interval == 0)
		return -EINVAL;

	 
	st->buckets = (st->stop - st->start) / st->interval + 3;
	if (st->buckets > BPF_HIST_MAX_BUCKETS || st->buckets < 3)
		return -EINVAL;

	return 0;
}



BPF_CALL_3(bpf_percpu_hash_stat_lookup_elem, struct bpf_map *, map, void *, key,
	   struct bpf_stat_cfg *, cfg)
{
	struct bpf_stat_data *sd;
	struct bpf_hist_data *st;
	int ret;

	sd = htab_percpu_map_ops.map_lookup_elem(map, key);
	if (sd)
		return (unsigned long)sd;

	 
	if (!cfg)
		return (unsigned long)NULL;

	sd = this_cpu_ptr(pcpu_sd_init_val);
	*sd = (typeof(*sd)){
		.cfg = *cfg,
		.min = S64_MAX,
		.max = S64_MIN
	};

	st = &sd->cfg.hist;
	switch (st->type) {
	case BPF_F_HIST_LOG:
		st->buckets = HIST_LOG_BUCKETS;
		break;
	case BPF_F_HIST_LINEAR:
		ret = hist_linear_calc_buckets(st);
		if (ret)
			return ret;
		break;
	default:
		break;
	}

	 
	ret = bpf_percpu_hash_update(map, key, sd, BPF_NOEXIST, true);
	if (ret && ret != -EEXIST)
		return (unsigned long)NULL;

	return (unsigned long)htab_percpu_map_ops.map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_percpu_hash_stat_lookup_elem_proto = {
	.func		= bpf_percpu_hash_stat_lookup_elem,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};




static int hist_val_to_bucket(int64_t val)
{
	int neg = 0, res = HIST_LOG_BUCKETS;

	if (val == 0)
		return HIST_LOG_BUCKET0;

	if (val < 0) {
		val = -val;
		neg = 1;
	}

	 
	if (unlikely(val & 0xffffffffffff0000ull)) {
		if (!(val & 0xffffffff00000000ull)) {
			val <<= 32;
			res -= 32;
		}

		if (!(val & 0xffff000000000000ull)) {
			val <<= 16;
			res -= 16;
		}
	} else {
		val <<= 48;
		res -= 48;
	}

	if (!(val & 0xff00000000000000ull)) {
		val <<= 8;
		res -= 8;
	}

	if (!(val & 0xf000000000000000ull)) {
		val <<= 4;
		res -= 4;
	}

	if (!(val & 0xc000000000000000ull)) {
		val <<= 2;
		res -= 2;
	}

	if (!(val & 0x8000000000000000ull)) {
		val <<= 1;
		res -= 1;
	}
	if (neg)
		res = HIST_LOG_BUCKETS - res;

	return res;
}

BPF_CALL_2(bpf_stat_add, struct bpf_stat_data *, sd, int64_t, val)
{
	struct bpf_stat_cfg *cfg = &sd->cfg;
	struct bpf_hist_data *st = &cfg->hist;

	if (unlikely(sd->count == 0)) {
		sd->count = 1;
		sd->sum = sd->min = sd->max = val;
		sd->avg_s = val << cfg->shift;
		sd->_M2 = 0;
	} else {
		sd->count++;
		sd->sum += val;
		if (unlikely(val > sd->max))
			sd->max = val;
		if (unlikely(val < sd->min))
			sd->min = val;
		



		if (cfg->opt & BPF_F_STAT_VARIANCE) {
			int delta = (val << cfg->shift) - sd->avg_s;
			sd->avg_s += delta / sd->count;
			sd->_M2 += delta * ((val << cfg->shift) - sd->avg_s);
			sd->variance_s = (sd->count < 2) ? -1 : sd->_M2 / (sd->count - 1);
		}
	}

	switch (st->type) {
	case BPF_F_HIST_LOG: {
		int n = hist_val_to_bucket(val);
		if (n >= st->buckets)
			n = st->buckets - 1;
		sd->histogram[n]++;
		break;
	}
	case BPF_F_HIST_LINEAR:
		val -= st->start;

		 
		if (val < 0)
			val = 0;
		else {
			uint64_t tmp = val;

			do_div(tmp, st->interval);
			val = tmp;
			val++;
		}

		 
		if (val >= st->buckets - 1)
			val = st->buckets - 1;

		sd->histogram[val]++;
		break;
	default:
		break;
	}

	return 0;
}

const struct bpf_func_proto bpf_stat_add_proto = {
	.func		= bpf_stat_add,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_stat_agg, struct bpf_stat_data *, sd, int64_t *, output,
	   uint64_t, opt, bool, onallcpus)
{
	struct bpf_stat_cfg *cfg = &sd->cfg;
	unsigned int cpu;

	 
	if (unlikely(hweight64(opt) != 1 || !(opt & cfg->opt)))
		return -EINVAL;

	if (onallcpus) {
		int64_t agg_min = sd->min, agg_max = sd->max;
		int64_t agg_count = 0, agg_sum = 0;

		 
		sd = (typeof(sd))(((unsigned long)sd) - __my_cpu_offset);
		for_each_possible_cpu(cpu) {
			struct bpf_stat_data *sdp = per_cpu_ptr(sd, cpu);

			 
			agg_count += sdp->count;

			switch (opt) {
			case BPF_F_STAT_SUM:
				agg_sum += sdp->sum;
				break;
			case BPF_F_STAT_MIN:
				if (unlikely(sdp->min < agg_min))
					agg_min = sdp->min;
				break;
			case BPF_F_STAT_MAX:
				if (unlikely(sdp->max > agg_max))
					agg_max = sdp->max;
				break;
			case BPF_F_STAT_AVG:
			case BPF_F_STAT_VARIANCE:
				 
				agg_sum += sdp->sum;
				break;
			default:
				 
				break;
			}
		}

		switch (opt) {
		case BPF_F_STAT_COUNT:
			*output = agg_count;
			break;
		case BPF_F_STAT_SUM:
			if (unlikely(!agg_count))
				return -ENODATA;

			*output = agg_sum;
			break;
		case BPF_F_STAT_MIN:
			if (unlikely(!agg_count))
				return -ENODATA;

			*output = agg_min;
			break;
		case BPF_F_STAT_MAX:
			if (unlikely(!agg_count))
				return -ENODATA;

			*output = agg_max;
			break;
		case BPF_F_STAT_AVG:
			if (unlikely(!agg_count))
				return -ENODATA;

			*output = agg_sum / agg_count;
			break;
		case BPF_F_STAT_VARIANCE: {
			int64_t S1 = 0, S2 = 0, agg_avg;

			if (unlikely(!agg_count))
				return -ENODATA;

			if (unlikely(agg_count == 1)) {
				*output = 0;
				break;
			}

			agg_avg = (agg_sum << cfg->shift) / agg_count;
			for_each_possible_cpu(cpu) {
				struct bpf_stat_data *sdp = per_cpu_ptr(sd, cpu);

				if (!sdp->count)
					continue;

				S1 += sdp->count * (sdp->avg_s - agg_avg) *
				      (sdp->avg_s - agg_avg);
				S2 += (sdp->count - 1) * sdp->variance_s;
			}

			*output = ((S1 + S2) / (agg_count - 1)) >>
				  (2 * cfg->shift);
			break;
		}
		}
	} else {
		switch (opt) {
		case BPF_F_STAT_COUNT:
			*output = sd->count;
			break;
		case BPF_F_STAT_SUM:
			if (unlikely(!sd->count))
				return -ENODATA;

			*output = sd->sum;
			break;
		case BPF_F_STAT_MIN:
			if (unlikely(!sd->count))
				return -ENODATA;

			*output = sd->min;
			break;
		case BPF_F_STAT_MAX:
			if (unlikely(!sd->count))
				return -ENODATA;

			*output = sd->max;
			break;
		case BPF_F_STAT_AVG:
			if (unlikely(!sd->count))
				return -ENODATA;

			*output = sd->sum / sd->count;
			break;
		case BPF_F_STAT_VARIANCE:
			if (unlikely(!sd->count))
				return -ENODATA;

			*output = sd->variance_s;
			break;
		}
	}

	return 0;
}

const struct bpf_func_proto bpf_stat_agg_proto = {
	.func		= bpf_stat_agg,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

static int needed_space(int64_t v)
{
	int space = 0;
	uint64_t tmp;

	if (v == 0)
		return 1;

	if (v < 0) {
		space++;
		v = -v;
	}
	tmp = v;
	while (tmp) {
		 
		do_div(tmp, 10);
		space++;
	}
	return space;
}

static int64_t hist_bucket_to_val(int num)
{
	if (num == HIST_LOG_BUCKET0)
		return 0;
	if (num < HIST_LOG_BUCKET0) {
		int64_t val = 0x8000000000000000LL;
		return  val >> num;
	} else
		return 1LL << (num - HIST_LOG_BUCKET0 - 1);
}

static long sprint_histogram(struct bpf_hist_data *st, s64 *histogram, char *buf,
			    u32 size)
{
	int scale, i, j, val_space, cnt_space;
	int low_bucket = -1, high_bucket = 0, over = 0, under = 0;
	int64_t val, valmax = 0;
	uint64_t v;
	int eliding = 0;
	char *cur_buf = buf;
	char *end = buf + size;

#define HIST_PRINTF(fmt, args...) \
	(cur_buf += scnprintf(cur_buf, end - cur_buf, fmt, ## args))

	

	for (i = 0; i < st->buckets; i++) {
		if (histogram[i] > 0 && low_bucket == -1)
			low_bucket = i;
		if (histogram[i] > 0)
			high_bucket = i;
		if (histogram[i] > valmax)
			valmax = histogram[i];
	}

	

	for (i = 0; i < 2; i++) {
		if (st->type == BPF_F_HIST_LOG) {
			 
			 
			if (low_bucket != HIST_LOG_BUCKET0 && low_bucket > 0)
				low_bucket--;
		} else {
			if (low_bucket > 0)
				low_bucket--;
		}
		if (high_bucket < (st->buckets-1))
			high_bucket++;
	}
	if (st->type == BPF_F_HIST_LINEAR) {
		 
		if (low_bucket == 0 && histogram[0] == 0)
			low_bucket++;
		if (high_bucket == st->buckets-1 && histogram[high_bucket] == 0)
			high_bucket--;
		if (low_bucket == 0)
			under = 1;
		if (high_bucket == st->buckets-1)
			over = 1;
	}

	if (valmax <= HIST_WIDTH)
		scale = 1;
	else {
		uint64_t tmp = valmax;
		int rem = do_div(tmp, HIST_WIDTH);
		scale = tmp;
		if (rem) scale++;
	}

	 
	cnt_space = needed_space(valmax);

	 
	if (st->type == BPF_F_HIST_LINEAR) {
		val_space = max(needed_space(st->start) + under,
				needed_space(st->start +  st->interval * high_bucket) + over);
	} else {
		val_space = max(needed_space(hist_bucket_to_val(high_bucket)),
				needed_space(hist_bucket_to_val(low_bucket)));
	}
	val_space = max(val_space, 5  );

	 
	HIST_PRINTF("%*s |", val_space, "value");
	for (j = 0; j < HIST_WIDTH; ++j)
		HIST_PRINTF("-");
	HIST_PRINTF(" count\n");

	eliding = 0;
	for (i = low_bucket; i <= high_bucket; i++) {
		const char *val_prefix = "";

		



		if ((long)HIST_ELISION >= 0) {
			int k, elide = 1;
			 
			int max_elide = min_t(long, HIST_ELISION, st->buckets);
			int min_bucket = low_bucket;
			int max_bucket = high_bucket;

			if (i - max_elide > min_bucket)
				min_bucket = i - max_elide;
			if (i + max_elide < max_bucket)
				max_bucket = i + max_elide;
			for (k = min_bucket; k <= max_bucket; k++) {
				if (histogram[k] != 0)
					elide = 0;
			}
			if (elide) {
				eliding = 1;
				continue;
			}

			


			if (eliding) {
				HIST_PRINTF("%*s ~\n", val_space, "");
				eliding = 0;
			}
		}

		if (st->type == BPF_F_HIST_LINEAR) {
			if (i == 0) {
				 
				val = st->start;
				val_prefix = "<";
			} else if (i == st->buckets-1) {
				 
				val = st->start + (int64_t)(i - 2) * st->interval;
				val_prefix = ">";
			} else
				val = st->start + (int64_t)(i - 1) * st->interval;
		} else
			val = hist_bucket_to_val(i);

		HIST_PRINTF("%*s%lld |", val_space - needed_space(val), val_prefix, val);

		 
		v = histogram[i];
		do_div(v, scale);

		for (j = 0; j < v; ++j)
			HIST_PRINTF("@");
		HIST_PRINTF("%*lld\n", (int)(HIST_WIDTH - v + 1 + cnt_space), histogram[i]);
	}
	HIST_PRINTF("\n");
#undef HIST_PRINTF

	return cur_buf - buf;
}



BPF_CALL_4(bpf_stat_hist, struct bpf_stat_data *, sd, char *, output,
	   u32, size, bool, onallcpus)
{
	struct bpf_stat_cfg *cfg = &sd->cfg;
	struct bpf_hist_data *st = &cfg->hist;

	if (unlikely(st->type != BPF_F_HIST_LOG &&
		     st->type != BPF_F_HIST_LINEAR))
		return 0;

	if (onallcpus) {
		s64 *agg_histogram = this_cpu_ptr(pcpu_agg_histogram);
		unsigned int cpu;
		int i;

		memset(agg_histogram, 0, sizeof(s64) * BPF_HIST_MAX_BUCKETS);

		 
		sd = (typeof(sd))(((unsigned long)sd) - __my_cpu_offset);
		for_each_possible_cpu(cpu) {
			struct bpf_stat_data *sdp = per_cpu_ptr(sd, cpu);

			for (i = 0; i < st->buckets; i++)
				agg_histogram[i] += sdp->histogram[i];
		}

		return sprint_histogram(st, agg_histogram, output, size);
	}

	return sprint_histogram(st, sd->histogram, output, size);
}

const struct bpf_func_proto bpf_stat_hist_proto = {
	.func		= bpf_stat_hist,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_0(bpf_getpgid)
{
	return pid_vnr(task_pgrp(current));
}

const struct bpf_func_proto bpf_getpgid_proto = {
	.func		= bpf_getpgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.func		= bpf_user_rnd_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_smp_processor_id)
{
	return smp_processor_id();
}

const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	.func		= bpf_get_smp_processor_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_cycles)
{
	return get_cycles();
}

const struct bpf_func_proto bpf_get_cycles_proto = {
	.func		= bpf_get_cycles,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_numa_node_id)
{
	return numa_node_id();
}

const struct bpf_func_proto bpf_get_numa_node_id_proto = {
	.func		= bpf_get_numa_node_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_ns)
{
	 
	return ktime_get_mono_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.func		= bpf_ktime_get_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_boot_ns)
{
	 
	return ktime_get_boot_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_boot_ns_proto = {
	.func		= bpf_ktime_get_boot_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_coarse_ns)
{
	return ktime_get_coarse_ns();
}

const struct bpf_func_proto bpf_ktime_get_coarse_ns_proto = {
	.func		= bpf_ktime_get_coarse_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_gettimeofday_ns)
{
	return ktime_get_real_fast_ns();
}

const struct bpf_func_proto bpf_gettimeofday_ns_proto = {
	.func		= bpf_gettimeofday_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_1(bpf_get_real_pid, pid_t, pid_nr)
{
	struct task_struct *curr_task = current;
	struct task_struct *task;
	struct pid *pid;

	if (unlikely(!pid_nr || pid_nr < 0 || !curr_task || !curr_task->mm
		     || !curr_task->pid))
		return -EINVAL;

	rcu_read_lock();
	pid = find_vpid(pid_nr);
	if (!pid) {
		goto failed;
	}
	task = pid_task(pid, PIDTYPE_PID);
	if (!task) {
		goto failed;
	}
	pid_nr = task->pid;
	rcu_read_unlock();
	return pid_nr;

failed:

	rcu_read_unlock();
	return -EINVAL;
}

const struct bpf_func_proto bpf_get_real_pid_proto = {
	.func		= bpf_get_real_pid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_pid_tgid)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		return -EINVAL;

	return (u64) task->tgid << 32 | task->pid;
}

const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.func		= bpf_get_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_uid_gid)
{
	struct task_struct *task = current;
	kuid_t uid;
	kgid_t gid;

	if (unlikely(!task))
		return -EINVAL;

	current_uid_gid(&uid, &gid);
	return (u64) from_kgid(&init_user_ns, gid) << 32 |
		     from_kuid(&init_user_ns, uid);
}

const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.func		= bpf_get_current_uid_gid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_2(bpf_get_current_comm, char *, buf, u32, size)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		goto err_clear;

	strncpy(buf, task->comm, size);

	



	buf[size - 1] = 0;
	return 0;
err_clear:
	memset(buf, 0, size);
	return -EINVAL;
}

const struct bpf_func_proto bpf_get_current_comm_proto = {
	.func		= bpf_get_current_comm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

#if defined(CONFIG_QUEUED_SPINLOCKS) || defined(CONFIG_BPF_ARCH_SPINLOCK)

static inline void __bpf_spin_lock(struct bpf_spin_lock *lock)
{
	arch_spinlock_t *l = (void *)lock;
	union {
		__u32 val;
		arch_spinlock_t lock;
	} u = { .lock = __ARCH_SPIN_LOCK_UNLOCKED };

	compiletime_assert(u.val == 0, "__ARCH_SPIN_LOCK_UNLOCKED not 0");
	BUILD_BUG_ON(sizeof(*l) != sizeof(__u32));
	BUILD_BUG_ON(sizeof(*lock) != sizeof(__u32));
	arch_spin_lock(l);
}

static inline void __bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	arch_spinlock_t *l = (void *)lock;

	arch_spin_unlock(l);
}

#else

static inline void __bpf_spin_lock(struct bpf_spin_lock *lock)
{
	atomic_t *l = (void *)lock;

	BUILD_BUG_ON(sizeof(*l) != sizeof(*lock));
	do {
		atomic_cond_read_relaxed(l, !VAL);
	} while (atomic_xchg(l, 1));
}

static inline void __bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	atomic_t *l = (void *)lock;

	atomic_set_release(l, 0);
}

#endif



notrace BPF_CALL_1(bpf_spin_lock, struct bpf_spin_lock *, lock)
{
	unsigned long flags;

	local_irq_save(flags);
	__bpf_spin_lock(lock);
	__this_cpu_write(*irqsave_flags, flags);
	return 0;
}

const struct bpf_func_proto bpf_spin_lock_proto = {
	.func		= bpf_spin_lock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
};

notrace BPF_CALL_1(bpf_spin_unlock, struct bpf_spin_lock *, lock)
{
	unsigned long flags;

	flags = __this_cpu_read(*irqsave_flags);
	__bpf_spin_unlock(lock);
	local_irq_restore(flags);
	return 0;
}

const struct bpf_func_proto bpf_spin_unlock_proto = {
	.func		= bpf_spin_unlock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
};

void orbpf_copy_map_value_locked(struct bpf_map *map, void *dst, void *src,
			   bool lock_src)
{
#if 1
	struct bpf_spin_lock *lock;

	if (lock_src)
		lock = src + map->spin_lock_off;
	else
		lock = dst + map->spin_lock_off;
	preempt_disable();
	____bpf_spin_lock(lock);
	orbpf_copy_map_value(map, dst, src);
	____bpf_spin_unlock(lock);
	preempt_enable();


#endif
}

BPF_CALL_0(bpf_jiffies64)
{
	return get_jiffies_64();
}

const struct bpf_func_proto bpf_jiffies64_proto = {
	.func		= bpf_jiffies64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};








































































#define BPF_STRTOX_BASE_MASK 0x1F

static int __bpf_strtoull(const char *buf, size_t buf_len, u64 flags,
			  unsigned long long *res, bool *is_negative)
{
	unsigned int base = flags & BPF_STRTOX_BASE_MASK;
	const char *cur_buf = buf;
	size_t cur_len = buf_len;
	unsigned int consumed;
	size_t val_len;
	char str[64];

	if (!buf || !buf_len || !res || !is_negative)
		return -EINVAL;

	if (base != 0 && base != 8 && base != 10 && base != 16)
		return -EINVAL;

	if (flags & ~BPF_STRTOX_BASE_MASK)
		return -EINVAL;

	while (cur_buf < buf + buf_len && isspace(*cur_buf))
		++cur_buf;

	*is_negative = (cur_buf < buf + buf_len && *cur_buf == '-');
	if (*is_negative)
		++cur_buf;

	consumed = cur_buf - buf;
	cur_len -= consumed;
	if (!cur_len)
		return -EINVAL;

	cur_len = min(cur_len, sizeof(str) - 1);
	memcpy(str, cur_buf, cur_len);
	str[cur_len] = '\0';
	cur_buf = str;

	cur_buf = _parse_integer_fixup_radix(cur_buf, &base);
	val_len = _parse_integer(cur_buf, base, res);

	if (val_len & KSTRTOX_OVERFLOW)
		return -ERANGE;

	if (val_len == 0)
		return -EINVAL;

	cur_buf += val_len;
	consumed += cur_buf - str;

	return consumed;
}

static int __bpf_strtoll(const char *buf, size_t buf_len, u64 flags,
			 long long *res)
{
	unsigned long long _res;
	bool is_negative;
	int err;

	err = __bpf_strtoull(buf, buf_len, flags, &_res, &is_negative);
	if (err < 0)
		return err;
	if (is_negative) {
		if ((long long)-_res > 0)
			return -ERANGE;
		*res = -_res;
	} else {
		if ((long long)_res < 0)
			return -ERANGE;
		*res = _res;
	}
	return err;
}

BPF_CALL_4(bpf_strtol, const char *, buf, size_t, buf_len, u64, flags,
	   long *, res)
{
	long long _res;
	int err;

	err = __bpf_strtoll(buf, buf_len, flags, &_res);
	if (err < 0)
		return err;
	if (_res != (long)_res)
		return -ERANGE;
	*res = _res;
	return err;
}

const struct bpf_func_proto bpf_strtol_proto = {
	.func		= bpf_strtol,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_LONG,
};

BPF_CALL_4(bpf_strtoul, const char *, buf, size_t, buf_len, u64, flags,
	   unsigned long *, res)
{
	unsigned long long _res;
	bool is_negative;
	int err;

	err = __bpf_strtoull(buf, buf_len, flags, &_res, &is_negative);
	if (err < 0)
		return err;
	if (is_negative)
		return -EINVAL;
	if (_res != (unsigned long)_res)
		return -ERANGE;
	*res = _res;
	return err;
}

const struct bpf_func_proto bpf_strtoul_proto = {
	.func		= bpf_strtoul,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_LONG,
};

BPF_CALL_4(bpf_get_ns_current_pid_tgid, u64, dev, u64, ino,
	   struct bpf_pidns_info *, nsdata, u32, size)
{
	struct task_struct *task = current;
	struct pid_namespace *pidns;
	int err = -EINVAL;

	if (unlikely(size != sizeof(struct bpf_pidns_info)))
		goto clear;

	if (unlikely((u64)(dev_t)dev != dev))
		goto clear;

	if (unlikely(!task))
		goto clear;

	pidns = task_active_pid_ns(task);
	if (unlikely(!pidns)) {
		err = -ENOENT;
		goto clear;
	}

#if defined(ORBPF_CONF_NS_MATCH) || defined(ORBPF_CONF_NS_COMMON)
	if (!ns_match(&pidns->ns, (dev_t)dev, ino))
		goto clear;
#endif

	nsdata->pid = task_pid_nr_ns(task, pidns);
	nsdata->tgid = task_tgid_nr_ns(task, pidns);
	return 0;
clear:
	memset((void *)nsdata, 0, (size_t) size);
	return err;
}

const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto = {
	.func		= bpf_get_ns_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};

static const struct bpf_func_proto bpf_get_raw_smp_processor_id_proto = {
	.func		= bpf_get_raw_cpu_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_5(bpf_event_output_data, void *, ctx, struct bpf_map *, map,
	   u64, flags, void *, data, u64, size)
{
	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

const struct bpf_func_proto bpf_event_output_data_proto =  {
	.func		= bpf_event_output_data,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_CONST_MAP_PTR,
	.arg3_type      = ARG_ANYTHING,
	.arg4_type      = ARG_PTR_TO_MEM,
	.arg5_type      = ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_3(bpf_copy_from_user, void *, dst, u32, size,
	   const void __user *, user_ptr)
{
	int ret = copy_from_user(dst, user_ptr, size);

	if (unlikely(ret)) {
		memset(dst, 0, size);
		ret = -EFAULT;
	}

	return ret;
}

const struct bpf_func_proto bpf_copy_from_user_proto = {
	.func		= bpf_copy_from_user,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_per_cpu_ptr, const void *, ptr, u32, cpu)
{
	if (cpu >= nr_cpu_ids)
		return (unsigned long)NULL;

	return (unsigned long)per_cpu_ptr((const void __percpu *)ptr, cpu);
}

const struct bpf_func_proto bpf_per_cpu_ptr_proto = {
	.func		= bpf_per_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_this_cpu_ptr, const void *, percpu_ptr)
{
	return (unsigned long)this_cpu_ptr((const void __percpu *)percpu_ptr);
}

const struct bpf_func_proto bpf_this_cpu_ptr_proto = {
	.func		= bpf_this_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
};

static int bpf_trace_copy_string(char *buf, void *unsafe_ptr, char fmt_ptype,
		size_t bufsz)
{
	void __user *user_ptr = (__force void __user *)unsafe_ptr;

	buf[0] = 0;

	switch (fmt_ptype) {
	case 's':
#ifdef CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
		if ((unsigned long)unsafe_ptr < TASK_SIZE)
			return orbpf_strncpy_from_user_nofault(buf, user_ptr, bufsz);
		fallthrough;
#endif
	case 'k':
		return strncpy_from_kernel_nofault(buf, unsafe_ptr, bufsz);
	case 'u':
		return orbpf_strncpy_from_user_nofault(buf, user_ptr, bufsz);
	}

	return -EINVAL;
}




#define MAX_BPRINTF_BUF_LEN	640

 
#define MAX_BPRINTF_NEST_LEVEL	3
struct bpf_bprintf_buffers {
	char tmp_bufs[MAX_BPRINTF_NEST_LEVEL][MAX_BPRINTF_BUF_LEN];
};



static int try_get_fmt_tmp_buf(char **tmp_buf)
{
	struct bpf_bprintf_buffers *bufs;
	int nest_level;

	preempt_disable();
	nest_level = this_cpu_inc_return(*bpf_bprintf_nest_level);
	if (WARN_ON_ONCE(nest_level > MAX_BPRINTF_NEST_LEVEL)) {
		this_cpu_dec(*bpf_bprintf_nest_level);
		preempt_enable();
		return -EBUSY;
	}
	bufs = this_cpu_ptr(bpf_bprintf_bufs);
	*tmp_buf = bufs->tmp_bufs[nest_level - 1];

	return 0;
}

void bpf_bprintf_cleanup(void)
{
	if (this_cpu_read(*bpf_bprintf_nest_level)) {
		this_cpu_dec(*bpf_bprintf_nest_level);
		preempt_enable();
	}
}















int bpf_bprintf_prepare(char *fmt, u32 fmt_size, const u64 *raw_args,
			u32 **bin_args, u32 num_args)
{
	char *unsafe_ptr = NULL, *tmp_buf = NULL, *tmp_buf_end = NULL, *fmt_end;
	size_t sizeof_cur_arg, sizeof_cur_ip;
	int err, i, num_spec = 0;
	u64 cur_arg;
	char fmt_ptype, cur_ip[16], ip_spec[] = "%pXX";

	fmt_end = strnchr(fmt, fmt_size, 0);
	if (!fmt_end)
		return -EINVAL;
	fmt_size = fmt_end - fmt;

	if (bin_args) {
		if (num_args && try_get_fmt_tmp_buf(&tmp_buf))
			return -EBUSY;

		tmp_buf_end = tmp_buf + MAX_BPRINTF_BUF_LEN;
		*bin_args = (u32 *)tmp_buf;
	}

	for (i = 0; i < fmt_size; i++) {
		if ((!isprint(fmt[i]) && !isspace(fmt[i])) || !isascii(fmt[i])) {
			err = -EINVAL;
			goto out;
		}

		if (fmt[i] != '%')
			continue;

		if (fmt[i + 1] == '%') {
			i++;
			continue;
		}

		if (num_spec >= num_args) {
			err = -EINVAL;
			goto out;
		}

		


		i++;

		 
		while (fmt[i] == '0' || fmt[i] == '+'  || fmt[i] == '-' ||
		       fmt[i] == ' ')
			i++;
		if (fmt[i] >= '1' && fmt[i] <= '9') {
			i++;
			while (fmt[i] >= '0' && fmt[i] <= '9')
				i++;
		}

		if (fmt[i] == 'p') {
			sizeof_cur_arg = sizeof(long);

			if ((fmt[i + 1] == 'k' || fmt[i + 1] == 'u') &&
			    fmt[i + 2] == 's') {
				fmt_ptype = fmt[i + 1];
				i += 2;
				goto fmt_str;
			}

			if (fmt[i + 1] == 0 || isspace(fmt[i + 1]) ||
			    ispunct(fmt[i + 1]) || fmt[i + 1] == 'K' ||
			    fmt[i + 1] == 'x' || fmt[i + 1] == 's' ||
			    fmt[i + 1] == 'S') {
				 
				if (tmp_buf)
					cur_arg = raw_args[num_spec];
				i++;
				goto nocopy_fmt;
			}

			if (fmt[i + 1] == 'B') {
				if (tmp_buf)  {
					err = snprintf(tmp_buf,
						       (tmp_buf_end - tmp_buf),
						       "%pB",
						       (void *)(long)raw_args[num_spec]);
					tmp_buf += (err + 1);
				}

				i++;
				num_spec++;
				continue;
			}

			 
			if ((fmt[i + 1] != 'i' && fmt[i + 1] != 'I') ||
			    (fmt[i + 2] != '4' && fmt[i + 2] != '6')) {
				err = -EINVAL;
				goto out;
			}

			i += 2;
			if (!tmp_buf)
				goto nocopy_fmt;

			sizeof_cur_ip = (fmt[i] == '4') ? 4 : 16;
			if (tmp_buf_end - tmp_buf < sizeof_cur_ip) {
				err = -ENOSPC;
				goto out;
			}

			unsafe_ptr = (char *)(long)raw_args[num_spec];
			err = copy_from_kernel_nofault(cur_ip, unsafe_ptr,
						       sizeof_cur_ip);
			if (err < 0)
				memset(cur_ip, 0, sizeof_cur_ip);

			



			ip_spec[2] = fmt[i - 1];
			ip_spec[3] = fmt[i];
			err = snprintf(tmp_buf, tmp_buf_end - tmp_buf,
				       ip_spec, &cur_ip);

			tmp_buf += err + 1;
			num_spec++;

			continue;
		} else if (fmt[i] == 's') {
			fmt_ptype = fmt[i];
fmt_str:









			if (!tmp_buf)
				goto nocopy_fmt;

			if (tmp_buf_end == tmp_buf) {
				err = -ENOSPC;
				goto out;
			}

			unsafe_ptr = (char *)(long)raw_args[num_spec];
			err = bpf_trace_copy_string(tmp_buf, unsafe_ptr,
						    fmt_ptype,
						    tmp_buf_end - tmp_buf);
			if (err < 0) {
				tmp_buf[0] = '\0';
				err = 1;
			}

			tmp_buf += err;
			num_spec++;

			continue;
		}

		sizeof_cur_arg = sizeof(int);

		if (fmt[i] == 'l') {
			sizeof_cur_arg = sizeof(long);
			i++;
		}
		if (fmt[i] == 'l') {
			sizeof_cur_arg = sizeof(long long);
			i++;
		}
		if (fmt[i] == 'f')
			sizeof_cur_arg = sizeof(uint64_t);

		if (fmt[i] != 'i' && fmt[i] != 'd' && fmt[i] != 'u' &&
		    fmt[i] != 'x' && fmt[i] != 'X' && fmt[i] != 'f') {
			err = -EINVAL;
			goto out;
		}

		if (tmp_buf)
			cur_arg = raw_args[num_spec];
nocopy_fmt:
		if (tmp_buf) {
			tmp_buf = PTR_ALIGN(tmp_buf, sizeof(u32));
			if (tmp_buf_end - tmp_buf < sizeof_cur_arg) {
				err = -ENOSPC;
				goto out;
			}

			if (sizeof_cur_arg == 8) {
				*(u32 *)tmp_buf = *(u32 *)&cur_arg;
				*(u32 *)(tmp_buf + 4) = *((u32 *)&cur_arg + 1);
			} else {
				*(u32 *)tmp_buf = (u32)(long)cur_arg;
			}
			tmp_buf += sizeof_cur_arg;
		}
		num_spec++;
	}

	err = 0;
out:
	if (err)
		bpf_bprintf_cleanup();
	return err;
}

#define MAX_SNPRINTF_VARARGS		12

BPF_CALL_5(bpf_snprintf, char *, str, u32, str_size, char *, fmt,
	   const void *, data, u32, data_len)
{
	int err, num_args;
	u32 *bin_args;











	if (unlikely(str_size > INT_MAX)) {


#if 1
		unsigned len;
		const char *label = orbpf_get_running_prog_label(&len);
		if (unlikely(label == NULL))
			return -EINVAL;

		pr_err("bpf_snprintf() got a huge str size: %u: %.*s\n",
		       str_size, (int) len, label);
#endif   
		return -EINVAL;
	}

	if (data_len % 8 || data_len > MAX_SNPRINTF_VARARGS * 8 ||
	    (data_len && !data))
		return -EINVAL;
	num_args = data_len / 8;

	


	err = bpf_bprintf_prepare(fmt, UINT_MAX, data, &bin_args, num_args);
	if (err < 0)
		return err;

	err = bstr_printf(str, str_size, fmt, bin_args);

	bpf_bprintf_cleanup();

	return err + 1;
}

const struct bpf_func_proto bpf_snprintf_proto = {
	.func		= bpf_snprintf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
	.arg4_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

__nocfi
BPF_CALL_4(bpf_call_func, void *, func, void *, data,
	   u32, data_len, int *, retval)
{
	int num_args;
	u64 *args = data;

	if (data_len % 8 || data_len > MAX_SNPRINTF_VARARGS * 8 ||
	    (data_len && !data))
		return -EINVAL;
	num_args = data_len / 8;

	switch (num_args) {
	case 0:
		*retval = ((int (*)(void)) func)();
		break;
	case 1:
		*retval = ((int (*)(u64)) func)(args[0]);
		break;
	case 2:
		*retval = ((int (*)(u64, u64)) func)(args[0], args[1]);
		break;
	case 3:
		*retval = ((int (*)(u64, u64, u64)) func)(args[0], args[1],
							  args[2]);
		break;
	case 4:
		*retval = ((int (*)(u64, u64, u64, u64)) func)(args[0],
							       args[1],
							       args[2],
							       args[3]);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

const struct bpf_func_proto bpf_call_func_proto = {
	.func		= bpf_call_func,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_FUNC,
	.arg2_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_PTR_TO_INT,
};

BPF_CALL_1(bpf_i64_to_f64, int64_t, n)
{
	return i64_to_f64(n).v;
}

const struct bpf_func_proto bpf_i64_to_f64_proto = {
	.func		= bpf_i64_to_f64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_u64_to_f64, uint64_t, n)
{
	return ui64_to_f64(n).v;
}

const struct bpf_func_proto bpf_u64_to_f64_proto = {
	.func		= bpf_u64_to_f64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_i32_to_f64, int32_t, n)
{
	return i32_to_f64(n).v;
}

const struct bpf_func_proto bpf_i32_to_f64_proto = {
	.func		= bpf_i32_to_f64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_u32_to_f64, uint32_t, n)
{
	return ui32_to_f64(n).v;
}

const struct bpf_func_proto bpf_u32_to_f64_proto = {
	.func		= bpf_u32_to_f64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_to_i32, uint64_t, n)
{
	float64_t f;
	f.v = n;
	return f64_to_i32_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f64_to_i32_proto = {
	.func		= bpf_f64_to_i32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_to_u32, uint64_t, n)
{
	float64_t f;
	f.v = n;
	return f64_to_ui32_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f64_to_u32_proto = {
	.func		= bpf_f64_to_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_to_i64, uint64_t, n)
{
	float64_t f;
	f.v = n;
	return f64_to_i64_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f64_to_i64_proto = {
	.func		= bpf_f64_to_i64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_to_u64, uint64_t, n)
{
	float64_t f;
	f.v = n;
	return f64_to_ui64_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f64_to_u64_proto = {
	.func		= bpf_f64_to_u64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_to_f64, uint32_t, n)
{
	float32_t f;
	f.v = n;
	return f32_to_f64(f).v;
}

const struct bpf_func_proto bpf_f32_to_f64_proto = {
	.func		= bpf_f32_to_f64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_to_f32, uint64_t, n)
{
	float64_t f;
	f.v = n;
	return f64_to_f32(f).v;
}

const struct bpf_func_proto bpf_f64_to_f32_proto = {
	.func		= bpf_f64_to_f32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_to_i32, uint32_t, n)
{
	float32_t f;
	f.v = n;
	return f32_to_i32_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f32_to_i32_proto = {
	.func		= bpf_f32_to_i32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_to_u32, uint32_t, n)
{
	float32_t f;
	f.v = n;
	return f32_to_ui32_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f32_to_u32_proto = {
	.func		= bpf_f32_to_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_to_i64, uint32_t, n)
{
	float32_t f;
	f.v = n;
	return f32_to_i64_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f32_to_i64_proto = {
	.func		= bpf_f32_to_i64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_to_u64, uint32_t, n)
{
	float32_t f;
	f.v = n;
	return f32_to_ui64_r_minMag(f, 0);
}

const struct bpf_func_proto bpf_f32_to_u64_proto = {
	.func		= bpf_f32_to_u64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_i32_to_f32, int32_t, n)
{
	return i32_to_f32(n).v;
}

const struct bpf_func_proto bpf_i32_to_f32_proto = {
	.func		= bpf_i32_to_f32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_u32_to_f32, uint32_t, n)
{
	return ui32_to_f32(n).v;
}

const struct bpf_func_proto bpf_u32_to_f32_proto = {
	.func		= bpf_u32_to_f32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_i64_to_f32, int64_t, n)
{
	return i64_to_f32(n).v;
}

const struct bpf_func_proto bpf_i64_to_f32_proto = {
	.func		= bpf_i64_to_f32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_u64_to_f32, uint64_t, n)
{
	return ui64_to_f32(n).v;
}

const struct bpf_func_proto bpf_u64_to_f32_proto = {
	.func		= bpf_u64_to_f32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_add, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_add(fa, fb).v;
}

const struct bpf_func_proto bpf_f64_add_proto = {
	.func		= bpf_f64_add,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_sub, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_sub(fa, fb).v;
}

const struct bpf_func_proto bpf_f64_sub_proto = {
	.func		= bpf_f64_sub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_mul, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_mul(fa, fb).v;
}

const struct bpf_func_proto bpf_f64_mul_proto = {
	.func		= bpf_f64_mul,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_div, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_div(fa, fb).v;
}

const struct bpf_func_proto bpf_f64_div_proto = {
	.func		= bpf_f64_div,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_mod, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb, quo;
	fa.v = a;
	fb.v = b;
	quo = f64_roundToInt(f64_div(fa, fb), softfloat_round_minMag, false);
	return f64_sub(fa, f64_mul(fb, quo)).v;
}

const struct bpf_func_proto bpf_f64_mod_proto = {
	.func		= bpf_f64_mod,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_rem, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_rem(fa, fb).v;
}

const struct bpf_func_proto bpf_f64_rem_proto = {
	.func		= bpf_f64_rem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_sqrt, uint64_t, n)
{
	float64_t f;
	f.v = n;
	return f64_sqrt(f).v;
}

const struct bpf_func_proto bpf_f64_sqrt_proto = {
	.func		= bpf_f64_sqrt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_neg, uint64_t, n)
{
	return f64_neg(n);
}

const struct bpf_func_proto bpf_f64_neg_proto = {
	.func		= bpf_f64_neg,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f64_abs, uint64_t, n)
{
	return f64_abs(n);
}

const struct bpf_func_proto bpf_f64_abs_proto = {
	.func		= bpf_f64_abs,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_add, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_add(fa, fb).v;
}

const struct bpf_func_proto bpf_f32_add_proto = {
	.func		= bpf_f32_add,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_sub, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_sub(fa, fb).v;
}

const struct bpf_func_proto bpf_f32_sub_proto = {
	.func		= bpf_f32_sub,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_mul, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_mul(fa, fb).v;
}

const struct bpf_func_proto bpf_f32_mul_proto = {
	.func		= bpf_f32_mul,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_div, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_div(fa, fb).v;
}

const struct bpf_func_proto bpf_f32_div_proto = {
	.func		= bpf_f32_div,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_mod, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb, quo;
	fa.v = a;
	fb.v = b;
	quo = f32_roundToInt(f32_div(fa, fb), softfloat_round_minMag, false);
	return f32_sub(fa, f32_mul(fb, quo)).v;
}

const struct bpf_func_proto bpf_f32_mod_proto = {
	.func		= bpf_f32_mod,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_rem, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_rem(fa, fb).v;
}

const struct bpf_func_proto bpf_f32_rem_proto = {
	.func		= bpf_f32_rem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_sqrt, uint32_t, n)
{
	float32_t f;
	f.v = n;
	return f32_sqrt(f).v;
}

const struct bpf_func_proto bpf_f32_sqrt_proto = {
	.func		= bpf_f32_sqrt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_neg, uint32_t, n)
{
	return f32_neg(n);
}

const struct bpf_func_proto bpf_f32_neg_proto = {
	.func		= bpf_f32_neg,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_f32_abs, uint32_t, n)
{
	return f32_abs(n);
}

const struct bpf_func_proto bpf_f32_abs_proto = {
	.func		= bpf_f32_abs,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_lt, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_lt_quiet(fa, fb);
}

const struct bpf_func_proto bpf_f64_lt_proto = {
	.func		= bpf_f64_lt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_le, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_le_quiet(fa, fb);
}

const struct bpf_func_proto bpf_f64_le_proto = {
	.func		= bpf_f64_le,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f64_eq, uint64_t, a, uint64_t, b)
{
	float64_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f64_eq(fa, fb);
}

const struct bpf_func_proto bpf_f64_eq_proto = {
	.func		= bpf_f64_eq,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_lt, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_lt_quiet(fa, fb);
}

const struct bpf_func_proto bpf_f32_lt_proto = {
	.func		= bpf_f32_lt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_le, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_le_quiet(fa, fb);
}

const struct bpf_func_proto bpf_f32_le_proto = {
	.func		= bpf_f32_le,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_f32_eq, uint32_t, a, uint32_t, b)
{
	float32_t fa, fb;
	fa.v = a;
	fb.v = b;
	return f32_eq(fa, fb);
}

const struct bpf_func_proto bpf_f32_eq_proto = {
	.func		= bpf_f32_eq,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_get_uregs, struct pt_regs *, regs, u32, size)
{
	size = min((size_t) size, sizeof(struct pt_regs));

	 
	if (unlikely(current->flags & PF_KTHREAD))
		return -ESRCH;

	if (unlikely(!try_get_task_stack(current)))
		return -EFAULT;

	memcpy(regs, task_pt_regs(current), size);

	put_task_stack(current);

	return 0;
}

const struct bpf_func_proto bpf_get_uregs_proto = {
	.func		= bpf_get_uregs,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};


BPF_CALL_1(bpf_get_tcb, u64, reg_val)
{
#ifdef __i386
	unsigned long gs;
	rdmsrl(MSR_FS_BASE, gs);
	return gs;
#elif defined __x86_64
	unsigned long fs;
	rdmsrl(MSR_FS_BASE, fs);
	return fs;

#elif defined __s390x__
	unsigned long tlsval;
	asm volatile ("ear %0,%%a0" : "=r" (tlsval));
	asm volatile ("sllg %0,%0,32" : "=r" (tlsval));
	asm volatile ("ear %0,%%a1" : "=r" (tlsval));
	return tlsval;

#elif defined __aarch64__
	unsigned long tlsval;
	asm("mrs %0,tpidr_el0" : "=r" (tlsval));
	return tlsval;

#elif defined __powerpc64__
	unsigned long tcb;
	asm("subi %0,%1,28688," : "=r" (tcb) : "r" (reg_val)); 
	return tcb;
#endif
}

const struct bpf_func_proto bpf_get_tcb_proto = {
	.func		= bpf_get_tcb,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_pr_err, const char *, msg)
{
    pr_err("%s\n", msg);
    return 0;
}

const struct bpf_func_proto bpf_pr_err_proto = {
	.func		= bpf_pr_err,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_get_current_task_proto __weak;
const struct bpf_func_proto bpf_probe_read_user_proto __weak;
const struct bpf_func_proto bpf_probe_read_user_str_proto __weak;
const struct bpf_func_proto bpf_probe_read_kernel_proto __weak;
const struct bpf_func_proto bpf_probe_read_kernel_str_proto __weak;

const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_strtol:
		return &bpf_strtol_proto;
	case BPF_FUNC_hash_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_percpu_hash_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_hash_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_percpu_hash_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_hash_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_hash_map_clear:
		return &bpf_map_clear_proto;
	case BPF_FUNC_hash_map_get_next_key:
		return &bpf_map_get_next_key_proto;
	case BPF_FUNC_percpu_hash_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_percpu_hash_map_clear:
		return &bpf_map_clear_proto;
	case BPF_FUNC_percpu_hash_map_get_next_key:
		return &bpf_map_get_next_key_proto;
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_map_clear:
		return &bpf_map_clear_proto;
	case BPF_FUNC_map_push_elem:
		return &bpf_map_push_elem_proto;
	case BPF_FUNC_map_pop_elem:
		return &bpf_map_pop_elem_proto;
	case BPF_FUNC_map_peek_elem:
		return &bpf_map_peek_elem_proto;
	case BPF_FUNC_map_get_next_key:
		return &bpf_map_get_next_key_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_raw_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;




	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	case BPF_FUNC_ktime_get_coarse_ns:
		return &bpf_ktime_get_coarse_ns_proto;
	case BPF_FUNC_ringbuf_output:
		return &bpf_ringbuf_output_proto;
	case BPF_FUNC_ringbuf_reserve:
		return &bpf_ringbuf_reserve_proto;
	case BPF_FUNC_ringbuf_submit:
		return &bpf_ringbuf_submit_proto;
	case BPF_FUNC_ringbuf_discard:
		return &bpf_ringbuf_discard_proto;
	case BPF_FUNC_ringbuf_query:
		return &bpf_ringbuf_query_proto;
#if 1
	case BPF_FUNC_for_each_map_elem:
		return &bpf_for_each_map_elem_proto;
#endif
	case BPF_FUNC_percpu_hash_stat_lookup_elem:
		return &bpf_percpu_hash_stat_lookup_elem_proto;
	case BPF_FUNC_stat_add:
		return &bpf_stat_add_proto;
	case BPF_FUNC_stat_agg:
		return &bpf_stat_agg_proto;
	case BPF_FUNC_stat_hist:
		return &bpf_stat_hist_proto;
	case BPF_FUNC_gettimeofday_ns:
		return &bpf_gettimeofday_ns_proto;
	case BPF_FUNC_getpgid:
		return &bpf_getpgid_proto;
	case BPF_FUNC_get_cycles:
		return &bpf_get_cycles_proto;
	case BPF_FUNC_hash_map_sort:
		return &bpf_hash_map_sort_proto;
	case BPF_FUNC_call_func:
		return &bpf_call_func_proto;
	case BPF_FUNC_i64_to_f64:
		return &bpf_i64_to_f64_proto;
	case BPF_FUNC_u64_to_f64:
		return &bpf_u64_to_f64_proto;
	case BPF_FUNC_i32_to_f64:
		return &bpf_i32_to_f64_proto;
	case BPF_FUNC_u32_to_f64:
		return &bpf_u32_to_f64_proto;
	case BPF_FUNC_f64_to_i32:
		return &bpf_f64_to_i32_proto;
	case BPF_FUNC_f64_to_u32:
		return &bpf_f64_to_u32_proto;
	case BPF_FUNC_f64_to_i64:
		return &bpf_f64_to_i64_proto;
	case BPF_FUNC_f64_to_u64:
		return &bpf_f64_to_u64_proto;
	case BPF_FUNC_f32_to_f64:
		return &bpf_f32_to_f64_proto;
	case BPF_FUNC_f64_to_f32:
		return &bpf_f64_to_f32_proto;
	case BPF_FUNC_f32_to_i32:
		return &bpf_f32_to_i32_proto;
	case BPF_FUNC_f32_to_u32:
		return &bpf_f32_to_u32_proto;
	case BPF_FUNC_f32_to_i64:
		return &bpf_f32_to_i64_proto;
	case BPF_FUNC_f32_to_u64:
		return &bpf_f32_to_u64_proto;
	case BPF_FUNC_i32_to_f32:
		return &bpf_i32_to_f32_proto;
	case BPF_FUNC_u32_to_f32:
		return &bpf_u32_to_f32_proto;
	case BPF_FUNC_i64_to_f32:
		return &bpf_i64_to_f32_proto;
	case BPF_FUNC_u64_to_f32:
		return &bpf_u64_to_f32_proto;
	case BPF_FUNC_f64_add:
		return &bpf_f64_add_proto;
	case BPF_FUNC_f64_sub:
		return &bpf_f64_sub_proto;
	case BPF_FUNC_f64_mul:
		return &bpf_f64_mul_proto;
	case BPF_FUNC_f64_div:
		return &bpf_f64_div_proto;
	case BPF_FUNC_f64_mod:
		return &bpf_f64_mod_proto;
	case BPF_FUNC_f64_rem:
		return &bpf_f64_rem_proto;
	case BPF_FUNC_f64_sqrt:
		return &bpf_f64_sqrt_proto;
	case BPF_FUNC_f64_neg:
		return &bpf_f64_neg_proto;
	case BPF_FUNC_f64_abs:
		return &bpf_f64_abs_proto;
	case BPF_FUNC_f32_add:
		return &bpf_f32_add_proto;
	case BPF_FUNC_f32_sub:
		return &bpf_f32_sub_proto;
	case BPF_FUNC_f32_mul:
		return &bpf_f32_mul_proto;
	case BPF_FUNC_f32_div:
		return &bpf_f32_div_proto;
	case BPF_FUNC_f32_mod:
		return &bpf_f32_mod_proto;
	case BPF_FUNC_f32_rem:
		return &bpf_f32_rem_proto;
	case BPF_FUNC_f32_sqrt:
		return &bpf_f32_sqrt_proto;
	case BPF_FUNC_f32_neg:
		return &bpf_f32_neg_proto;
	case BPF_FUNC_f32_abs:
		return &bpf_f32_abs_proto;
	case BPF_FUNC_f64_lt:
		return &bpf_f64_lt_proto;
	case BPF_FUNC_f64_le:
		return &bpf_f64_le_proto;
	case BPF_FUNC_f64_eq:
		return &bpf_f64_eq_proto;
	case BPF_FUNC_f32_lt:
		return &bpf_f32_lt_proto;
	case BPF_FUNC_f32_le:
		return &bpf_f32_le_proto;
	case BPF_FUNC_f32_eq:
		return &bpf_f32_eq_proto;
	case BPF_FUNC_get_uregs:
		return &bpf_get_uregs_proto;
	case BPF_FUNC_get_tcb:
		return &bpf_get_tcb_proto;
	case BPF_FUNC_pr_err:
		return &bpf_pr_err_proto;
	default:
		break;
	}

	if (!bpf_capable())
		return NULL;

	switch (func_id) {
	case BPF_FUNC_spin_lock:
		return &bpf_spin_lock_proto;
	case BPF_FUNC_spin_unlock:
		return &bpf_spin_unlock_proto;
	case BPF_FUNC_jiffies64:
		return &bpf_jiffies64_proto;
	case BPF_FUNC_per_cpu_ptr:
		return &bpf_per_cpu_ptr_proto;
	case BPF_FUNC_this_cpu_ptr:
		return &bpf_this_cpu_ptr_proto;
	default:
		break;
	}

	if (!perfmon_capable())
		return NULL;

	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_probe_read_user:
		return &bpf_probe_read_user_proto;
	case BPF_FUNC_probe_read_kernel:
		return &bpf_probe_read_kernel_proto;
	case BPF_FUNC_probe_read_user_str:
		return &bpf_probe_read_user_str_proto;
	case BPF_FUNC_probe_read_kernel_str:
		return &bpf_probe_read_kernel_str_proto;
	case BPF_FUNC_snprintf_btf:
		return &bpf_snprintf_btf_proto;
	case BPF_FUNC_snprintf:
		return &bpf_snprintf_proto;
	default:
		return NULL;
	}
}

int bpf_pcpu_pcpu_sd_init_val_init0(void) { pcpu_sd_init_val = alloc_percpu(struct bpf_stat_data); if (unlikely(pcpu_sd_init_val == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_pcpu_agg_histogram_init0(void) { pcpu_agg_histogram = (s64  *) alloc_percpu(s64 [BPF_HIST_MAX_BUCKETS]); if (unlikely(pcpu_agg_histogram == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_irqsave_flags_init0(void) { irqsave_flags = alloc_percpu(unsigned long); if (unlikely(irqsave_flags == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_bpf_bprintf_bufs_init0(void) { bpf_bprintf_bufs = alloc_percpu(struct bpf_bprintf_buffers); if (unlikely(bpf_bprintf_bufs == NULL)) { return -ENOMEM; } return 0; } int bpf_pcpu_bpf_bprintf_nest_level_init0(void) { bpf_bprintf_nest_level = alloc_percpu(int); if (unlikely(bpf_bprintf_nest_level == NULL)) { return -ENOMEM; } return 0; }
void bpf_pcpu_pcpu_sd_init_val_exit0(void) { free_percpu(pcpu_sd_init_val); } void bpf_pcpu_pcpu_agg_histogram_exit0(void) { free_percpu(pcpu_agg_histogram); } void bpf_pcpu_irqsave_flags_exit0(void) { free_percpu(irqsave_flags); } void bpf_pcpu_bpf_bprintf_bufs_exit0(void) { free_percpu(bpf_bprintf_bufs); } void bpf_pcpu_bpf_bprintf_nest_level_exit0(void) { free_percpu(bpf_bprintf_nest_level); }