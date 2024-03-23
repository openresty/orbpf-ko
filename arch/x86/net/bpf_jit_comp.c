/* Copyright (C) by OpenResty Inc. All rights reserved. */






#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <linux/bpf.h>
#include <linux/memory.h>
#include <linux/sort.h>
#include <asm/extable.h>
#include <asm/set_memory.h>
#include <asm/nospec-branch.h>
#include <asm/text-patching.h>
#include <asm/asm-prototypes.h>
#include <linux/orbpf_config_begin.h>  

#ifndef RETPOLINE_RCX_BPF_JIT  





















#ifdef CONFIG_RETPOLINE
# ifdef CONFIG_X86_64
#  define RETPOLINE_RCX_BPF_JIT_SIZE	17
#  define RETPOLINE_RCX_BPF_JIT()				\
do {								\
	EMIT1_off32(0xE8, 7);	  		\
	 					\
	EMIT2(0xF3, 0x90);        			\
	EMIT3(0x0F, 0xAE, 0xE8);  			\
	EMIT2(0xEB, 0xF9);        		\
	 						\
	EMIT4(0x48, 0x89, 0x0C, 0x24);  	\
	EMIT1(0xC3);              			\
} while (0)
# else  
#  define RETPOLINE_EDX_BPF_JIT()				\
do {								\
	EMIT1_off32(0xE8, 7);	  		\
	 					\
	EMIT2(0xF3, 0x90);        			\
	EMIT3(0x0F, 0xAE, 0xE8);  			\
	EMIT2(0xEB, 0xF9);        		\
	 						\
	EMIT3(0x89, 0x14, 0x24);  		\
	EMIT1(0xC3);              			\
} while (0)
# endif
#else  
# ifdef CONFIG_X86_64
#  define RETPOLINE_RCX_BPF_JIT_SIZE	2
#  define RETPOLINE_RCX_BPF_JIT()				\
	EMIT2(0xFF, 0xE1);        
# else  
#  define RETPOLINE_EDX_BPF_JIT()				\
	EMIT2(0xFF, 0xE2)         
# endif
#endif
#endif  













#define BYTES_NOP1	0x90
#define BYTES_NOP2	0x66,BYTES_NOP1
#define BYTES_NOP3	0x0f,0x1f,0x00
#define BYTES_NOP4	0x0f,0x1f,0x40,0x00
#define BYTES_NOP5	0x0f,0x1f,0x44,0x00,0x00
#define BYTES_NOP6	0x66,BYTES_NOP5
#define BYTES_NOP7	0x0f,0x1f,0x80,0x00,0x00,0x00,0x00
#define BYTES_NOP8	0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00

const unsigned char x86nops[] =
{
	BYTES_NOP1,
	BYTES_NOP2,
	BYTES_NOP3,
	BYTES_NOP4,
	BYTES_NOP5,
	BYTES_NOP6,
	BYTES_NOP7,
	BYTES_NOP8,
};

const unsigned char * const x86_nops[ASM_NOP_MAX+1] =
{
	NULL,
	x86nops,
	x86nops + 1,
	x86nops + 1 + 2,
	x86nops + 1 + 2 + 3,
	x86nops + 1 + 2 + 3 + 4,
	x86nops + 1 + 2 + 3 + 4 + 5,
	x86nops + 1 + 2 + 3 + 4 + 5 + 6,
	x86nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
};

static u8 *emit_code(u8 *ptr, u32 bytes, unsigned int len)
{
	if (len == 1)
		*ptr = bytes;
	else if (len == 2)
		*(u16 *)ptr = bytes;
	else {
		*(u32 *)ptr = bytes;
		barrier();
	}
	return ptr + len;
}

#define EMIT(bytes, len) \
	do { prog = emit_code(prog, bytes, len); cnt += len; } while (0)

#define EMIT1(b1)		EMIT(b1, 1)
#define EMIT2(b1, b2)		EMIT((b1) + ((b2) << 8), 2)
#define EMIT3(b1, b2, b3)	EMIT((b1) + ((b2) << 8) + ((b3) << 16), 3)
#define EMIT4(b1, b2, b3, b4)   EMIT((b1) + ((b2) << 8) + ((b3) << 16) + ((b4) << 24), 4)

#define EMIT1_off32(b1, off) \
	do { EMIT1(b1); EMIT(off, 4); } while (0)
#define EMIT2_off32(b1, b2, off) \
	do { EMIT2(b1, b2); EMIT(off, 4); } while (0)
#define EMIT3_off32(b1, b2, b3, off) \
	do { EMIT3(b1, b2, b3); EMIT(off, 4); } while (0)
#define EMIT4_off32(b1, b2, b3, b4, off) \
	do { EMIT4(b1, b2, b3, b4); EMIT(off, 4); } while (0)

static bool is_imm8(int value)
{
	return value <= 127 && value >= -128;
}

static bool is_simm32(s64 value)
{
	return value == (s64)(s32)value;
}

static bool is_uimm32(u64 value)
{
	return value == (u64)(u32)value;
}

 
#define EMIT_mov(DST, SRC)								 \
	do {										 \
		if (DST != SRC)								 \
			EMIT3(add_2mod(0x48, DST, SRC), 0x89, add_2reg(0xC0, DST, SRC)); \
	} while (0)

static int bpf_size_to_x86_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 4;  
	else
		return 0;
}





#define X86_JB  0x72
#define X86_JAE 0x73
#define X86_JE  0x74
#define X86_JNE 0x75
#define X86_JBE 0x76
#define X86_JA  0x77
#define X86_JL  0x7C
#define X86_JGE 0x7D
#define X86_JLE 0x7E
#define X86_JG  0x7F

 
#define AUX_REG (MAX_BPF_JIT_REG + 1)
#define X86_REG_R9 (MAX_BPF_JIT_REG + 2)











static const int reg2hex[] = {
	[BPF_REG_0] = 0,   
	[BPF_REG_1] = 7,   
	[BPF_REG_2] = 6,   
	[BPF_REG_3] = 2,   
	[BPF_REG_4] = 1,   
	[BPF_REG_5] = 0,   
	[BPF_REG_6] = 3,   
	[BPF_REG_7] = 5,   
	[BPF_REG_8] = 6,   
	[BPF_REG_9] = 7,   
	[BPF_REG_FP] = 5,  
	[BPF_REG_AX] = 2,  
	[AUX_REG] = 3,     
	[X86_REG_R9] = 1,  
};

static const int reg2pt_regs[] = {
	[BPF_REG_0] = offsetof(struct pt_regs, ax),
	[BPF_REG_1] = offsetof(struct pt_regs, di),
	[BPF_REG_2] = offsetof(struct pt_regs, si),
	[BPF_REG_3] = offsetof(struct pt_regs, dx),
	[BPF_REG_4] = offsetof(struct pt_regs, cx),
	[BPF_REG_5] = offsetof(struct pt_regs, r8),
	[BPF_REG_6] = offsetof(struct pt_regs, bx),
	[BPF_REG_7] = offsetof(struct pt_regs, r13),
	[BPF_REG_8] = offsetof(struct pt_regs, r14),
	[BPF_REG_9] = offsetof(struct pt_regs, r15),
};






static bool is_ereg(u32 reg)
{
	return (1 << reg) & (BIT(BPF_REG_5) |
			     BIT(AUX_REG) |
			     BIT(BPF_REG_7) |
			     BIT(BPF_REG_8) |
			     BIT(BPF_REG_9) |
			     BIT(X86_REG_R9) |
			     BIT(BPF_REG_AX));
}






static bool is_ereg_8l(u32 reg)
{
	return is_ereg(reg) ||
	    (1 << reg) & (BIT(BPF_REG_1) |
			  BIT(BPF_REG_2) |
			  BIT(BPF_REG_FP));
}

static bool is_axreg(u32 reg)
{
	return reg == BPF_REG_0;
}

 
static u8 add_1mod(u8 byte, u32 reg)
{
	if (is_ereg(reg))
		byte |= 1;
	return byte;
}

static u8 add_2mod(u8 byte, u32 r1, u32 r2)
{
	if (is_ereg(r1))
		byte |= 1;
	if (is_ereg(r2))
		byte |= 4;
	return byte;
}

 
static u8 add_1reg(u8 byte, u32 dst_reg)
{
	return byte + reg2hex[dst_reg];
}

 
static u8 add_2reg(u8 byte, u32 dst_reg, u32 src_reg)
{
	return byte + reg2hex[dst_reg] + (reg2hex[src_reg] << 3);
}

 
static u8 simple_alu_opcodes[] = {
	[BPF_ADD] = 0x01,
	[BPF_SUB] = 0x29,
	[BPF_AND] = 0x21,
	[BPF_OR] = 0x09,
	[BPF_XOR] = 0x31,
	[BPF_LSH] = 0xE0,
	[BPF_RSH] = 0xE8,
	[BPF_ARSH] = 0xF8,
};

static void jit_fill_hole(void *area, unsigned int size)
{
	 
	memset(area, 0xcc, size);
}

struct jit_context {
	int cleanup_addr;  
};

 
#define BPF_MAX_INSN_SIZE	128
#define BPF_INSN_SAFETY		64

 
#define X86_PATCH_SIZE		5
 
#define X86_TAIL_CALL_OFFSET	11

static void push_callee_regs(u8 **pprog, bool *callee_regs_used)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (callee_regs_used[0])
		EMIT1(0x53);          
	if (callee_regs_used[1])
		EMIT2(0x41, 0x55);    
	if (callee_regs_used[2])
		EMIT2(0x41, 0x56);    
	if (callee_regs_used[3])
		EMIT2(0x41, 0x57);    
	*pprog = prog;
}

static void pop_callee_regs(u8 **pprog, bool *callee_regs_used)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (callee_regs_used[3])
		EMIT2(0x41, 0x5F);    
	if (callee_regs_used[2])
		EMIT2(0x41, 0x5E);    
	if (callee_regs_used[1])
		EMIT2(0x41, 0x5D);    
	if (callee_regs_used[0])
		EMIT1(0x5B);          
	*pprog = prog;
}






static void emit_prologue(u8 **pprog, u32 stack_depth, bool ebpf_from_cbpf,
			  bool tail_call_reachable, bool is_subprog)
{
	u8 *prog = *pprog;
	int cnt = X86_PATCH_SIZE;

	


	memcpy(prog, x86_nops[5], cnt);
	prog += cnt;
	if (!ebpf_from_cbpf) {
		if (tail_call_reachable && !is_subprog)
			EMIT2(0x31, 0xC0);  
		else
			EMIT2(0x66, 0x90);  
	}
	EMIT1(0x55);              
	EMIT3(0x48, 0x89, 0xE5);  
	 
	if (stack_depth)
		EMIT3_off32(0x48, 0x81, 0xEC, round_up(stack_depth, 8));
	if (tail_call_reachable)
		EMIT1(0x50);          
	*pprog = prog;
}

static int emit_patch(u8 **pprog, void *func, void *ip, u8 opcode)
{
	u8 *prog = *pprog;
	int cnt = 0;
	s64 offset;

	offset = func - (ip + X86_PATCH_SIZE);
	if (!is_simm32(offset)) {
		pr_err("Target call %p is out of range\n", func);
		return -ERANGE;
	}
	EMIT1_off32(opcode, offset);
	*pprog = prog;
	return 0;
}

static int emit_call(u8 **pprog, void *func, void *ip)
{
	return emit_patch(pprog, func, ip, 0xE8);
}






































































































































































































































































































static void emit_mov_imm32(u8 **pprog, bool sign_propagate,
			   u32 dst_reg, const u32 imm32)
{
	u8 *prog = *pprog;
	u8 b1, b2, b3;
	int cnt = 0;

	



	if (sign_propagate && (s32)imm32 < 0) {
		 
		b1 = add_1mod(0x48, dst_reg);
		b2 = 0xC7;
		b3 = 0xC0;
		EMIT3_off32(b1, b2, add_1reg(b3, dst_reg), imm32);
		goto done;
	}

	



	if (imm32 == 0) {
		if (is_ereg(dst_reg))
			EMIT1(add_2mod(0x40, dst_reg, dst_reg));
		b2 = 0x31;  
		b3 = 0xC0;
		EMIT2(b2, add_2reg(b3, dst_reg, dst_reg));
		goto done;
	}

	 
	if (is_ereg(dst_reg))
		EMIT1(add_1mod(0x40, dst_reg));
	EMIT1_off32(add_1reg(0xB8, dst_reg), imm32);
done:
	*pprog = prog;
}

static void emit_mov_imm64(u8 **pprog, u32 dst_reg,
			   const u32 imm32_hi, const u32 imm32_lo)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is_uimm32(((u64)imm32_hi << 32) | (u32)imm32_lo)) {
		





		emit_mov_imm32(&prog, false, dst_reg, imm32_lo);
	} else {
		 
		EMIT2(add_1mod(0x48, dst_reg), add_1reg(0xB8, dst_reg));
		EMIT(imm32_lo, 4);
		EMIT(imm32_hi, 4);
	}

	*pprog = prog;
}

static void emit_mov_reg(u8 **pprog, bool is64, u32 dst_reg, u32 src_reg)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is64) {
		 
		EMIT_mov(dst_reg, src_reg);
	} else {
		 
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT1(add_2mod(0x40, dst_reg, src_reg));
		EMIT2(0x89, add_2reg(0xC0, dst_reg, src_reg));
	}

	*pprog = prog;
}

 
static void emit_insn_suffix(u8 **pprog, u32 ptr_reg, u32 val_reg, int off)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is_imm8(off)) {
		





		EMIT2(add_2reg(0x40, ptr_reg, val_reg), off);
	} else {
		 
		EMIT1_off32(add_2reg(0x80, ptr_reg, val_reg), off);
	}
	*pprog = prog;
}




static void maybe_emit_mod(u8 **pprog, u32 dst_reg, u32 src_reg, bool is64)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is64)
		EMIT1(add_2mod(0x48, dst_reg, src_reg));
	else if (is_ereg(dst_reg) || is_ereg(src_reg))
		EMIT1(add_2mod(0x40, dst_reg, src_reg));
	*pprog = prog;
}

 
static void emit_ldx(u8 **pprog, u32 size, u32 dst_reg, u32 src_reg, int off)
{
	u8 *prog = *pprog;
	int cnt = 0;

	switch (size) {
	case BPF_B:
		 
		EMIT3(add_2mod(0x48, src_reg, dst_reg), 0x0F, 0xB6);
		break;
	case BPF_H:
		 
		EMIT3(add_2mod(0x48, src_reg, dst_reg), 0x0F, 0xB7);
		break;
	case BPF_W:
		 
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT2(add_2mod(0x40, src_reg, dst_reg), 0x8B);
		else
			EMIT1(0x8B);
		break;
	case BPF_DW:
		 
		EMIT2(add_2mod(0x48, src_reg, dst_reg), 0x8B);
		break;
	}
	emit_insn_suffix(&prog, src_reg, dst_reg, off);
	*pprog = prog;
}

 
static void emit_stx(u8 **pprog, u32 size, u32 dst_reg, u32 src_reg, int off)
{
	u8 *prog = *pprog;
	int cnt = 0;

	switch (size) {
	case BPF_B:
		 
		if (is_ereg(dst_reg) || is_ereg_8l(src_reg))
			 
			EMIT2(add_2mod(0x40, dst_reg, src_reg), 0x88);
		else
			EMIT1(0x88);
		break;
	case BPF_H:
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT3(0x66, add_2mod(0x40, dst_reg, src_reg), 0x89);
		else
			EMIT2(0x66, 0x89);
		break;
	case BPF_W:
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT2(add_2mod(0x40, dst_reg, src_reg), 0x89);
		else
			EMIT1(0x89);
		break;
	case BPF_DW:
		EMIT2(add_2mod(0x48, dst_reg, src_reg), 0x89);
		break;
	}
	emit_insn_suffix(&prog, dst_reg, src_reg, off);
	*pprog = prog;
}

static int emit_atomic(u8 **pprog, u8 atomic_op,
		       u32 dst_reg, u32 src_reg, s16 off, u8 bpf_size)
{
	u8 *prog = *pprog;
	int cnt = 0;

	EMIT1(0xF0);  

	maybe_emit_mod(&prog, dst_reg, src_reg, bpf_size == BPF_DW);

	 
	switch (atomic_op) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		 
		EMIT1(simple_alu_opcodes[atomic_op]);
		break;
	case BPF_ADD | BPF_FETCH:
		 
		EMIT2(0x0F, 0xC1);
		break;
	case BPF_XCHG:
		 
		EMIT1(0x87);
		break;
	case BPF_CMPXCHG:
		 
		EMIT2(0x0F, 0xB1);
		break;
	default:
		pr_err("bpf_jit: unknown atomic opcode %02x\n", atomic_op);
		return -EFAULT;
	}

	emit_insn_suffix(&prog, dst_reg, src_reg, off);

	*pprog = prog;
	return 0;
}















static void detect_reg_usage(struct bpf_insn *insn, int insn_cnt,
			     bool *regs_used, bool *tail_call_seen)
{
	int i;

	for (i = 1; i <= insn_cnt; i++, insn++) {




		if (insn->dst_reg == BPF_REG_6 || insn->src_reg == BPF_REG_6)
			regs_used[0] = true;
		if (insn->dst_reg == BPF_REG_7 || insn->src_reg == BPF_REG_7)
			regs_used[1] = true;
		if (insn->dst_reg == BPF_REG_8 || insn->src_reg == BPF_REG_8)
			regs_used[2] = true;
		if (insn->dst_reg == BPF_REG_9 || insn->src_reg == BPF_REG_9)
			regs_used[3] = true;
	}
}

static int emit_nops(u8 **pprog, int len)
{
	u8 *prog = *pprog;
	int i, noplen, cnt = 0;

	while (len > 0) {
		noplen = len;

		if (noplen > ASM_NOP_MAX)
			noplen = ASM_NOP_MAX;

		for (i = 0; i < noplen; i++)
			EMIT1(x86_nops[noplen][i]);
		len -= noplen;
	}

	*pprog = prog;

	return cnt;
}

#define INSN_SZ_DIFF (((addrs[i] - addrs[i - 1]) - (prog - temp)))

static int do_jit(struct bpf_prog *bpf_prog, int *addrs, u8 *image,
		  int oldproglen, struct jit_context *ctx, bool jmp_padding)
{
	bool tail_call_reachable = false;
	struct bpf_insn *insn = bpf_prog->insnsi;
	bool callee_regs_used[4] = {};
	int insn_cnt = bpf_prog->len;
	bool tail_call_seen = false;
	bool seen_exit = false;
	u8 temp[BPF_MAX_INSN_SIZE + BPF_INSN_SAFETY];
	int i, cnt = 0;
	int ilen, proglen = 0;
	u8 *prog = temp;
	int err;

	detect_reg_usage(insn, insn_cnt, callee_regs_used,
			 &tail_call_seen);

	 
	tail_call_reachable |= tail_call_seen;

	emit_prologue(&prog, bpf_prog->aux->stack_depth,
		      bpf_prog_was_classic(bpf_prog), tail_call_reachable,
		      bpf_prog->aux->func_idx != 0);
	push_callee_regs(&prog, callee_regs_used);

	ilen = prog - temp;
	if (image)
		memcpy(image + proglen, temp, ilen);
	proglen += ilen;
	addrs[0] = proglen;
	prog = temp;

	for (i = 1; i <= insn_cnt; i++, insn++) {
		const s32 imm32 = insn->imm;
		u32 dst_reg = insn->dst_reg;
		u32 src_reg = insn->src_reg;
		u8 b2 = 0, b3 = 0;
		
		s64 jmp_offset;
		u8 jmp_cond;
		u8 *func;
		int nops;

		switch (insn->code) {
			 
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_ADD | BPF_X:
		case BPF_ALU64 | BPF_SUB | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			maybe_emit_mod(&prog, dst_reg, src_reg,
				       BPF_CLASS(insn->code) == BPF_ALU64);
			b2 = simple_alu_opcodes[BPF_OP(insn->code)];
			EMIT2(b2, add_2reg(0xC0, dst_reg, src_reg));
			break;

		case BPF_ALU64 | BPF_MOV | BPF_X:
		case BPF_ALU | BPF_MOV | BPF_X:
			emit_mov_reg(&prog,
				     BPF_CLASS(insn->code) == BPF_ALU64,
				     dst_reg, src_reg);
			break;

			 
		case BPF_ALU | BPF_NEG:
		case BPF_ALU64 | BPF_NEG:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));
			EMIT2(0xF7, add_1reg(0xD8, dst_reg));
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			



			switch (BPF_OP(insn->code)) {
			case BPF_ADD:
				b3 = 0xC0;
				b2 = 0x05;
				break;
			case BPF_SUB:
				b3 = 0xE8;
				b2 = 0x2D;
				break;
			case BPF_AND:
				b3 = 0xE0;
				b2 = 0x25;
				break;
			case BPF_OR:
				b3 = 0xC8;
				b2 = 0x0D;
				break;
			case BPF_XOR:
				b3 = 0xF0;
				b2 = 0x35;
				break;
			}

			if (is_imm8(imm32))
				EMIT3(0x83, add_1reg(b3, dst_reg), imm32);
			else if (is_axreg(dst_reg))
				EMIT1_off32(b2, imm32);
			else
				EMIT2_off32(0x81, add_1reg(b3, dst_reg), imm32);
			break;

		case BPF_ALU64 | BPF_MOV | BPF_K:
		case BPF_ALU | BPF_MOV | BPF_K:
			emit_mov_imm32(&prog, BPF_CLASS(insn->code) == BPF_ALU64,
				       dst_reg, imm32);
			break;

		case BPF_LD | BPF_IMM | BPF_DW:
			emit_mov_imm64(&prog, dst_reg, insn[1].imm, insn[0].imm);
			insn++;
			i++;
			break;

			 
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			EMIT1(0x50);  
			EMIT1(0x52);  

			if (BPF_SRC(insn->code) == BPF_X)
				 
				EMIT_mov(AUX_REG, src_reg);
			else
				 
				EMIT3_off32(0x49, 0xC7, 0xC3, imm32);

			 
			EMIT_mov(BPF_REG_0, dst_reg);

			



			EMIT2(0x31, 0xd2);

			if (BPF_CLASS(insn->code) == BPF_ALU64)
				 
				EMIT3(0x49, 0xF7, 0xF3);
			else
				 
				EMIT3(0x41, 0xF7, 0xF3);

			if (BPF_OP(insn->code) == BPF_MOD)
				 
				EMIT3(0x49, 0x89, 0xD3);
			else
				 
				EMIT3(0x49, 0x89, 0xC3);

			EMIT1(0x5A);  
			EMIT1(0x58);  

			 
			EMIT_mov(dst_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_X:
		{
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;

			if (dst_reg != BPF_REG_0)
				EMIT1(0x50);  
			if (dst_reg != BPF_REG_3)
				EMIT1(0x52);  

			 
			EMIT_mov(AUX_REG, dst_reg);

			if (BPF_SRC(insn->code) == BPF_X)
				emit_mov_reg(&prog, is64, BPF_REG_0, src_reg);
			else
				emit_mov_imm32(&prog, is64, BPF_REG_0, imm32);

			if (is64)
				EMIT1(add_1mod(0x48, AUX_REG));
			else if (is_ereg(AUX_REG))
				EMIT1(add_1mod(0x40, AUX_REG));
			 
			EMIT2(0xF7, add_1reg(0xE0, AUX_REG));

			if (dst_reg != BPF_REG_3)
				EMIT1(0x5A);  
			if (dst_reg != BPF_REG_0) {
				 
				EMIT_mov(dst_reg, BPF_REG_0);
				EMIT1(0x58);  
			}
			break;
		}
			 
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			b3 = simple_alu_opcodes[BPF_OP(insn->code)];
			if (imm32 == 1)
				EMIT2(0xD1, add_1reg(b3, dst_reg));
			else
				EMIT3(0xC1, add_1reg(b3, dst_reg), imm32);
			break;

		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_ARSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_RSH | BPF_X:
		case BPF_ALU64 | BPF_ARSH | BPF_X:

			 
			if (dst_reg == BPF_REG_4) {
				 
				EMIT_mov(AUX_REG, dst_reg);
				dst_reg = AUX_REG;
			}

			if (src_reg != BPF_REG_4) {  
				EMIT1(0x51);  

				 
				EMIT_mov(BPF_REG_4, src_reg);
			}

			 
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			b3 = simple_alu_opcodes[BPF_OP(insn->code)];
			EMIT2(0xD3, add_1reg(b3, dst_reg));

			if (src_reg != BPF_REG_4)
				EMIT1(0x59);  

			if (insn->dst_reg == BPF_REG_4)
				 
				EMIT_mov(insn->dst_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_END | BPF_FROM_BE:
			switch (imm32) {
			case 16:
				 
				EMIT1(0x66);
				if (is_ereg(dst_reg))
					EMIT1(0x41);
				EMIT3(0xC1, add_1reg(0xC8, dst_reg), 8);

				 
				if (is_ereg(dst_reg))
					EMIT3(0x45, 0x0F, 0xB7);
				else
					EMIT2(0x0F, 0xB7);
				EMIT1(add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 32:
				 
				if (is_ereg(dst_reg))
					EMIT2(0x41, 0x0F);
				else
					EMIT1(0x0F);
				EMIT1(add_1reg(0xC8, dst_reg));
				break;
			case 64:
				 
				EMIT3(add_1mod(0x48, dst_reg), 0x0F,
				      add_1reg(0xC8, dst_reg));
				break;
			}
			break;

		case BPF_ALU | BPF_END | BPF_FROM_LE:
			switch (imm32) {
			case 16:
				



				if (is_ereg(dst_reg))
					EMIT3(0x45, 0x0F, 0xB7);
				else
					EMIT2(0x0F, 0xB7);
				EMIT1(add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 32:
				 
				if (is_ereg(dst_reg))
					EMIT1(0x45);
				EMIT2(0x89, add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 64:
				 
				break;
			}
			break;

			 
		case BPF_ST | BPF_NOSPEC:
			if (boot_cpu_has(X86_FEATURE_XMM2))
				 
				EMIT3(0x0F, 0xAE, 0xE8);
			break;

			 
		case BPF_ST | BPF_MEM | BPF_B:
			if (is_ereg(dst_reg))
				EMIT2(0x41, 0xC6);
			else
				EMIT1(0xC6);
			goto st;
		case BPF_ST | BPF_MEM | BPF_H:
			if (is_ereg(dst_reg))
				EMIT3(0x66, 0x41, 0xC7);
			else
				EMIT2(0x66, 0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_W:
			if (is_ereg(dst_reg))
				EMIT2(0x41, 0xC7);
			else
				EMIT1(0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_DW:
			EMIT2(add_1mod(0x48, dst_reg), 0xC7);

st:			if (is_imm8(insn->off))
				EMIT2(add_1reg(0x40, dst_reg), insn->off);
			else
				EMIT1_off32(add_1reg(0x80, dst_reg), insn->off);

			EMIT(imm32, bpf_size_to_x86_bytes(BPF_SIZE(insn->code)));
			break;

			 
		case BPF_STX | BPF_MEM | BPF_B:
		case BPF_STX | BPF_MEM | BPF_H:
		case BPF_STX | BPF_MEM | BPF_W:
		case BPF_STX | BPF_MEM | BPF_DW:
			emit_stx(&prog, BPF_SIZE(insn->code), dst_reg, src_reg, insn->off);
			break;

			 
		case BPF_LDX | BPF_MEM | BPF_B:
		case BPF_LDX | BPF_MEM | BPF_H:
		case BPF_LDX | BPF_MEM | BPF_W:
		case BPF_LDX | BPF_MEM | BPF_DW:





















			emit_ldx(&prog, BPF_SIZE(insn->code), dst_reg, src_reg, insn->off);















































			break;

		case BPF_STX | BPF_ATOMIC | BPF_W:
		case BPF_STX | BPF_ATOMIC | BPF_DW:
			if (insn->imm == (BPF_AND | BPF_FETCH) ||
			    insn->imm == (BPF_OR | BPF_FETCH) ||
			    insn->imm == (BPF_XOR | BPF_FETCH)) {
				u8 *branch_target;
				bool is64 = BPF_SIZE(insn->code) == BPF_DW;
				u32 real_src_reg = src_reg;

				




				 
				emit_mov_reg(&prog, true, BPF_REG_AX, BPF_REG_0);
				if (src_reg == BPF_REG_0)
					real_src_reg = BPF_REG_AX;

				branch_target = prog;
				 
				emit_ldx(&prog, BPF_SIZE(insn->code),
					 BPF_REG_0, dst_reg, insn->off);
				



				emit_mov_reg(&prog, is64, AUX_REG, BPF_REG_0);
				maybe_emit_mod(&prog, AUX_REG, real_src_reg, is64);
				EMIT2(simple_alu_opcodes[BPF_OP(insn->imm)],
				      add_2reg(0xC0, AUX_REG, real_src_reg));
				 
				err = emit_atomic(&prog, BPF_CMPXCHG,
						  dst_reg, AUX_REG, insn->off,
						  BPF_SIZE(insn->code));
				if (WARN_ON(err))
					return err;
				



				EMIT2(X86_JNE, -(prog - branch_target) - 2);
				 
				emit_mov_reg(&prog, is64, real_src_reg, BPF_REG_0);
				 
				emit_mov_reg(&prog, true, BPF_REG_0, BPF_REG_AX);
				break;

			}

			err = emit_atomic(&prog, insn->imm, dst_reg, src_reg,
						  insn->off, BPF_SIZE(insn->code));
			if (err)
				return err;
			break;

			 
		case BPF_JMP | BPF_CALL:
			func = (u8 *) __bpf_call_base + imm32;
			if (tail_call_reachable) {
				EMIT3_off32(0x48, 0x8B, 0x85,
					    -(bpf_prog->aux->stack_depth + 8));
				if (!imm32 || emit_call(&prog, func, image + addrs[i - 1] + 7))
					return -EINVAL;
			} else {
				if (!imm32 || emit_call(&prog, func, image + addrs[i - 1]))
					return -EINVAL;
			}
			break;

		case BPF_JMP | BPF_TAIL_CALL:












			pr_err("tail calls not supported!\n");
			return -EINVAL;

			 
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JNE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JLT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JLE | BPF_X:
		case BPF_JMP | BPF_JSGT | BPF_X:
		case BPF_JMP | BPF_JSLT | BPF_X:
		case BPF_JMP | BPF_JSGE | BPF_X:
		case BPF_JMP | BPF_JSLE | BPF_X:
		case BPF_JMP32 | BPF_JEQ | BPF_X:
		case BPF_JMP32 | BPF_JNE | BPF_X:
		case BPF_JMP32 | BPF_JGT | BPF_X:
		case BPF_JMP32 | BPF_JLT | BPF_X:
		case BPF_JMP32 | BPF_JGE | BPF_X:
		case BPF_JMP32 | BPF_JLE | BPF_X:
		case BPF_JMP32 | BPF_JSGT | BPF_X:
		case BPF_JMP32 | BPF_JSLT | BPF_X:
		case BPF_JMP32 | BPF_JSGE | BPF_X:
		case BPF_JMP32 | BPF_JSLE | BPF_X:
			 
			maybe_emit_mod(&prog, dst_reg, src_reg,
				       BPF_CLASS(insn->code) == BPF_JMP);
			EMIT2(0x39, add_2reg(0xC0, dst_reg, src_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_X:
		case BPF_JMP32 | BPF_JSET | BPF_X:
			 
			maybe_emit_mod(&prog, dst_reg, src_reg,
				       BPF_CLASS(insn->code) == BPF_JMP);
			EMIT2(0x85, add_2reg(0xC0, dst_reg, src_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP32 | BPF_JSET | BPF_K:
			 
			if (BPF_CLASS(insn->code) == BPF_JMP)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));
			EMIT2_off32(0xF7, add_1reg(0xC0, dst_reg), imm32);
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JNE | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JLT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JLE | BPF_K:
		case BPF_JMP | BPF_JSGT | BPF_K:
		case BPF_JMP | BPF_JSLT | BPF_K:
		case BPF_JMP | BPF_JSGE | BPF_K:
		case BPF_JMP | BPF_JSLE | BPF_K:
		case BPF_JMP32 | BPF_JEQ | BPF_K:
		case BPF_JMP32 | BPF_JNE | BPF_K:
		case BPF_JMP32 | BPF_JGT | BPF_K:
		case BPF_JMP32 | BPF_JLT | BPF_K:
		case BPF_JMP32 | BPF_JGE | BPF_K:
		case BPF_JMP32 | BPF_JLE | BPF_K:
		case BPF_JMP32 | BPF_JSGT | BPF_K:
		case BPF_JMP32 | BPF_JSLT | BPF_K:
		case BPF_JMP32 | BPF_JSGE | BPF_K:
		case BPF_JMP32 | BPF_JSLE | BPF_K:
			 
			if (imm32 == 0) {
				maybe_emit_mod(&prog, dst_reg, dst_reg,
					       BPF_CLASS(insn->code) == BPF_JMP);
				EMIT2(0x85, add_2reg(0xC0, dst_reg, dst_reg));
				goto emit_cond_jmp;
			}

			 
			if (BPF_CLASS(insn->code) == BPF_JMP)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			if (is_imm8(imm32))
				EMIT3(0x83, add_1reg(0xF8, dst_reg), imm32);
			else
				EMIT2_off32(0x81, add_1reg(0xF8, dst_reg), imm32);

emit_cond_jmp:		 
			switch (BPF_OP(insn->code)) {
			case BPF_JEQ:
				jmp_cond = X86_JE;
				break;
			case BPF_JSET:
			case BPF_JNE:
				jmp_cond = X86_JNE;
				break;
			case BPF_JGT:
				 
				jmp_cond = X86_JA;
				break;
			case BPF_JLT:
				 
				jmp_cond = X86_JB;
				break;
			case BPF_JGE:
				 
				jmp_cond = X86_JAE;
				break;
			case BPF_JLE:
				 
				jmp_cond = X86_JBE;
				break;
			case BPF_JSGT:
				 
				jmp_cond = X86_JG;
				break;
			case BPF_JSLT:
				 
				jmp_cond = X86_JL;
				break;
			case BPF_JSGE:
				 
				jmp_cond = X86_JGE;
				break;
			case BPF_JSLE:
				 
				jmp_cond = X86_JLE;
				break;
			default:  
				return -EFAULT;
			}
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (is_imm8(jmp_offset)) {
				if (jmp_padding) {
					














					nops = INSN_SZ_DIFF - 2;
					if (nops != 0 && nops != 4) {
						pr_err("unexpected jmp_cond padding: %d bytes\n",
						       nops);
						return -EFAULT;
					}
					cnt += emit_nops(&prog, nops);
				}
				EMIT2(jmp_cond, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT2_off32(0x0F, jmp_cond + 0x10, jmp_offset);
			} else {
				pr_err("cond_jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}

			break;

		case BPF_JMP | BPF_JA:
			if (insn->off == -1)
				





				jmp_offset = -2;
			else
				jmp_offset = addrs[i + insn->off] - addrs[i];

			if (!jmp_offset) {
				



				if (jmp_padding) {
					









					nops = INSN_SZ_DIFF;
					if (nops != 0 && nops != 2 && nops != 5) {
						pr_err("unexpected nop jump padding: %d bytes\n",
						       nops);
						return -EFAULT;
					}
					cnt += emit_nops(&prog, nops);
				}
				break;
			}
emit_jmp:
			if (is_imm8(jmp_offset)) {
				if (jmp_padding) {
					











					nops = INSN_SZ_DIFF - 2;
					if (nops != 0 && nops != 3) {
						pr_err("unexpected jump padding: %d bytes\n",
						       nops);
						return -EFAULT;
					}
					cnt += emit_nops(&prog, INSN_SZ_DIFF - 2);
				}
				EMIT2(0xEB, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT1_off32(0xE9, jmp_offset);
			} else {
				pr_err("jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}
			break;

		case BPF_JMP | BPF_EXIT:
			if (seen_exit) {
				jmp_offset = ctx->cleanup_addr - addrs[i];
				goto emit_jmp;
			}
			seen_exit = true;
			 
			ctx->cleanup_addr = proglen;
			pop_callee_regs(&prog, callee_regs_used);
			EMIT1(0xC9);          
			EMIT1(0xC3);          
			break;

		default:
			





			pr_err("bpf_jit: unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}

		ilen = prog - temp;
		if (ilen > BPF_MAX_INSN_SIZE) {
			pr_err("bpf_jit: fatal insn size error\n");
			return -EFAULT;
		}

		if (image) {
			







			if (unlikely(proglen + ilen > oldproglen ||
				     proglen + ilen != addrs[i])) {
				pr_err("bpf_jit: fatal error\n");
				return -EFAULT;
			}
			memcpy(image + proglen, temp, ilen);
		}
		proglen += ilen;
		addrs[i] = proglen;
		prog = temp;
	}







	return proglen;
}
































































































































































































































































































































































































































































































struct x64_jit_data {
	struct bpf_binary_header *header;
	int *addrs;
	u8 *image;
	int proglen;
	struct jit_context ctx;
};

#define MAX_PASSES 20
#define PADDING_PASSES (MAX_PASSES - 5)

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	struct bpf_binary_header *header = NULL;
	struct bpf_prog *tmp, *orig_prog = prog;
	struct x64_jit_data *jit_data;
	int proglen, oldproglen = 0;
	struct jit_context ctx = {};
	bool tmp_blinded = false;
	bool extra_pass = false;
	bool padding = false;
	u8 *image = NULL;
	int *addrs;
	int pass;
	int i;

	if (!prog->jit_requested)
		return orig_prog;

	tmp = bpf_jit_blind_constants(prog);
	



	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}
	addrs = jit_data->addrs;
	if (addrs) {
		ctx = jit_data->ctx;
		oldproglen = jit_data->proglen;
		image = jit_data->image;
		header = jit_data->header;
		extra_pass = true;
		padding = true;
		goto skip_init_addrs;
	}
	addrs = kvmalloc_array(prog->len + 1, sizeof(*addrs), GFP_KERNEL);
	if (!addrs) {
		prog = orig_prog;
		goto out_addrs;
	}

	



	for (proglen = 0, i = 0; i <= prog->len; i++) {
		proglen += 64;
		addrs[i] = proglen;
	}
	ctx.cleanup_addr = proglen;
skip_init_addrs:

	





	for (pass = 0; pass < MAX_PASSES || image; pass++) {
		if (!padding && pass >= PADDING_PASSES)
			padding = true;
		proglen = do_jit(prog, addrs, image, oldproglen, &ctx, padding);
		if (proglen <= 0) {
out_image:
			image = NULL;
			if (header)
				bpf_jit_binary_free(header);
			prog = orig_prog;
			goto out_addrs;
		}
		if (image) {
			if (proglen != oldproglen) {
				pr_err("bpf_jit: proglen=%d != oldproglen=%d\n",
				       proglen, oldproglen);
				goto out_image;
			}
			break;
		}
		if (proglen == oldproglen) {














#if 1
			header = bpf_jit_binary_alloc(proglen, &image,
						      1, jit_fill_hole);
#endif
			if (!header) {
				prog = orig_prog;
				goto out_addrs;
			}
			
		}
		oldproglen = proglen;
		cond_resched();
	}

	if (bpf_jit_enable == 2)
		bpf_jit_dump(prog->len, proglen, pass + 1, image);

	if (image) {
		if (!prog->is_func || extra_pass) {
			
			bpf_jit_binary_lock_ro(header);
		} else {
			jit_data->addrs = addrs;
			jit_data->ctx = ctx;
			jit_data->proglen = proglen;
			jit_data->image = image;
			jit_data->header = header;
		}
		prog->bpf_func = (void *)image;
		prog->jited = 1;
		prog->jited_len = proglen;
	} else {
		prog = orig_prog;
	}

	if (!image || !prog->is_func || extra_pass) {
		if (image)
			bpf_prog_fill_jited_linfo(prog, addrs + 1);
out_addrs:
		kvfree(addrs);
		kfree(jit_data);
		prog->aux->jit_data = NULL;
	}
out:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	return prog;
}

bool bpf_jit_supports_kfunc_call(void)
{
	return true;
}