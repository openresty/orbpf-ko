/* Copyright (C) by OpenResty Inc. All rights reserved. */


#ifndef _ORBPF_LINUX_BPF_VERIFIER_H
#define _ORBPF_LINUX_BPF_VERIFIER_H 1

#include <linux/bpf.h>  
#include <linux/btf.h>  
#include <linux/filter.h>  

#include <linux/orbpf_config_begin.h>  





#define BPF_MAX_VAR_OFF	(1 << 29)



#define BPF_MAX_VAR_SIZ	(1 << 29)














enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,  
	REG_LIVE_READ32 = 0x1,  
	REG_LIVE_READ64 = 0x2,  
	REG_LIVE_READ = REG_LIVE_READ32 | REG_LIVE_READ64,
	REG_LIVE_WRITTEN = 0x4,  
	REG_LIVE_DONE = 0x8,  
};

struct bpf_reg_state {
	 
	enum bpf_reg_type type;
	 
	s32 off;
	union {
		 
		int range;

		


		struct bpf_map *map_ptr;

		 
		struct {
			struct btf *btf;
			u32 btf_id;
		};

		u32 mem_size;  

		 
		struct {
			unsigned long raw1;
			unsigned long raw2;
		} raw;

		u32 subprogno;  
	};
	








	u32 id;
	






































	u32 ref_obj_id;
	





	struct tnum var_off;
	




	s64 smin_value;  
	s64 smax_value;  
	u64 umin_value;  
	u64 umax_value;  
	s32 s32_min_value;  
	s32 s32_max_value;  
	u32 u32_min_value;  
	u32 u32_max_value;  
	 
	struct bpf_reg_state *parent;
	





	u32 frameno;
	



	s32 subreg_def;
	enum bpf_reg_liveness live;
	 
	bool precise;
};

enum bpf_stack_slot_type {
	STACK_INVALID,     
	STACK_SPILL,       
	STACK_MISC,	   
	STACK_ZERO,	   
};

#define BPF_REG_SIZE 8	 

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[BPF_REG_SIZE];
};

struct bpf_reference_state {
	


	int id;
	


	int insn_idx;
};




struct bpf_func_state {
	struct bpf_reg_state regs[MAX_BPF_REG];
	 
	int callsite;
	



	u32 frameno;
	


	u32 subprogno;

	 
	int acquired_refs;
	struct bpf_reference_state *refs;
	int allocated_stack;
	bool in_callback_fn;
	struct bpf_stack_state *stack;
};

struct bpf_idx_pair {
	u32 prev_idx;
	u32 idx;
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

 
#define BPF_ID_MAP_SIZE (MAX_BPF_REG + MAX_BPF_STACK / BPF_REG_SIZE)
#define MAX_CALL_FRAMES 16
struct bpf_verifier_state {
	 
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	struct bpf_verifier_state *parent;
	












































	u32 branches;
	u32 insn_idx;
	u32 curframe;
	u32 active_spin_lock;
	bool speculative;

	 
	u32 first_insn_idx;
	u32 last_insn_idx;
	




	struct bpf_idx_pair *jmp_history;
	u32 jmp_history_cnt;
};

#define bpf_get_spilled_reg(slot, frame)				\
	(((slot < frame->allocated_stack / BPF_REG_SIZE) &&		\
	  (frame->stack[slot].slot_type[0] == STACK_SPILL))		\
	 ? &frame->stack[slot].spilled_ptr : NULL)

 
#define bpf_for_each_spilled_reg(iter, frame, reg)			\
	for (iter = 0, reg = bpf_get_spilled_reg(iter, frame);		\
	     iter < frame->allocated_stack / BPF_REG_SIZE;		\
	     iter++, reg = bpf_get_spilled_reg(iter, frame))

 
struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt, hit_cnt;
};

 
#define BPF_ALU_SANITIZE_SRC		(1U << 0)
#define BPF_ALU_SANITIZE_DST		(1U << 1)
#define BPF_ALU_NEG_VALUE		(1U << 2)
#define BPF_ALU_NON_POINTER		(1U << 3)
#define BPF_ALU_IMMEDIATE		(1U << 4)
#define BPF_ALU_SANITIZE		(BPF_ALU_SANITIZE_SRC | \
					 BPF_ALU_SANITIZE_DST)

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;	 
		unsigned long map_ptr_state;	 
		s32 call_imm;			 
		u32 alu_limit;			 
		struct {
			u32 map_index;		 
			u32 map_off;		 
		};
		struct {
			enum bpf_reg_type reg_type;	 
			union {
				struct {
					struct btf *btf;
					u32 btf_id;	 
				};
				u32 mem_size;	 
			};
		} btf_var;
	};
	u64 map_key_state;  
	int ctx_field_size;  
	u32 seen;  
	bool sanitize_stack_spill;  
	bool zext_dst;  
	u8 alu_state;  

	 
	unsigned int orig_idx;  
	bool prune_point;
};

#define MAX_USED_MAPS 64  
#define MAX_USED_BTFS 64  

#define BPF_VERIFIER_TMP_LOG_SIZE	1024

struct bpf_verifier_log {
	u32 level;
	char kbuf[BPF_VERIFIER_TMP_LOG_SIZE];
	char __user *ubuf;
	u32 len_used;
	u32 len_total;
};

static inline bool bpf_verifier_log_full(const struct bpf_verifier_log *log)
{
	return log->len_used >= log->len_total - 1;
}

#define BPF_LOG_LEVEL1	1
#define BPF_LOG_LEVEL2	2
#define BPF_LOG_STATS	4
#define BPF_LOG_LEVEL	(BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2)
#define BPF_LOG_MASK	(BPF_LOG_LEVEL | BPF_LOG_STATS)
#define BPF_LOG_KERNEL	(BPF_LOG_MASK + 1)  

static inline bool bpf_verifier_log_needed(const struct bpf_verifier_log *log)
{
	return log &&
		((log->level && log->ubuf && !bpf_verifier_log_full(log)) ||
		 log->level == BPF_LOG_KERNEL);
}

#define BPF_MAX_SUBPROGS 256

struct bpf_subprog_info {
	 
	u32 start;  
	u32 linfo_idx;  
	u16 stack_depth;  
	bool has_tail_call;
	bool tail_call_reachable;
	bool has_ld_abs;
};




struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;		 
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head;  
	int stack_size;			 
	bool strict_alignment;		 
	bool test_state_freq;		 
	struct bpf_verifier_state *cur_state;  
	struct bpf_verifier_state_list **explored_states;  
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[MAX_USED_MAPS];  
	
	u32 used_map_cnt;		 
	u32 used_btf_cnt;		 
	u32 id_gen;			 
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool allow_ptr_to_map_access;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	struct bpf_insn_aux_data *insn_aux_data;  
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 1];
	struct bpf_id_pair idmap_scratch[BPF_ID_MAP_SIZE];
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	u32 pass_cnt;  
	u32 subprog_cnt;
	 
	u32 prev_insn_processed, insn_processed;
	 
	u32 prev_jmps_processed, jmps_processed;
	 
	u64 verification_time;
	 
	u32 max_states_per_insn;
	 
	u32 total_states;
	



	u32 peak_states;
	 
	u32 longest_mark_read_walk;



};

__printf(2, 0) void bpf_verifier_vlog(struct bpf_verifier_log *log,
				      const char *fmt, va_list args);
__printf(2, 3) void bpf_verifier_log_write(struct bpf_verifier_env *env,
					   const char *fmt, ...);
__printf(2, 3) void bpf_log(struct bpf_verifier_log *log,
			    const char *fmt, ...);

static inline struct bpf_func_state *cur_func(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[cur->curframe];
}

static inline struct bpf_reg_state *cur_regs(struct bpf_verifier_env *env)
{
	return cur_func(env)->regs;
}







void
bpf_prog_offload_replace_insn(struct bpf_verifier_env *env, u32 off,
			      struct bpf_insn *insn);
void
bpf_prog_offload_remove_insns(struct bpf_verifier_env *env, u32 off, u32 cnt);

int check_ctx_reg(struct bpf_verifier_env *env,
		  const struct bpf_reg_state *reg, int regno);
int check_mem_reg(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
		   u32 regno, u32 mem_size);

 
static inline u64 bpf_trampoline_compute_key(const struct bpf_prog *tgt_prog,
					     struct btf *btf, u32 btf_id)
{
	if (tgt_prog)
		return ((u64)tgt_prog->aux->id << 32) | btf_id;
	else
		return ((u64)btf_obj_id(btf) << 32) | 0x80000000 | btf_id;
}

 
static inline void bpf_trampoline_unpack_key(u64 key, u32 *obj_id, u32 *btf_id)
{
	if (obj_id)
		*obj_id = key >> 32;
	if (btf_id)
		*btf_id = key & 0x7FFFFFFF;
}

int bpf_check_attach_target(struct bpf_verifier_log *log,
			    const struct bpf_prog *prog,
			    const struct bpf_prog *tgt_prog,
			    u32 btf_id,
			    struct bpf_attach_target_info *tgt_info);

void bpf_dump_prog_jit_mcode(struct bpf_prog *prog);
void bpf_dump_prog_bc(struct bpf_verifier_env *env);

#include <linux/orbpf_config_end.h>  
#endif  