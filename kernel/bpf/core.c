/* Copyright (C) by OpenResty Inc. All rights reserved. */ #define DDEBUG 0



















#include <uapi/linux/btf.h>
#include <linux/filter.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/moduleloader.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include <linux/rbtree_latch.h>
#include <linux/kallsyms.h>
#include <linux/rcupdate.h>
#include <linux/perf_event.h>
#include <linux/extable.h>
#include <linux/log2.h>

#include <asm/barrier.h>
#include <asm/unaligned.h>
#include <linux/orbpf_config_begin.h>  
#include "mmap_unlock_work.h"

 
#define BPF_R0	regs[BPF_REG_0]
#define BPF_R1	regs[BPF_REG_1]
#define BPF_R2	regs[BPF_REG_2]
#define BPF_R3	regs[BPF_REG_3]
#define BPF_R4	regs[BPF_REG_4]
#define BPF_R5	regs[BPF_REG_5]
#define BPF_R6	regs[BPF_REG_6]
#define BPF_R7	regs[BPF_REG_7]
#define BPF_R8	regs[BPF_REG_8]
#define BPF_R9	regs[BPF_REG_9]
#define BPF_R10	regs[BPF_REG_10]

 
#define DST	regs[insn->dst_reg]
#define SRC	regs[insn->src_reg]
#define FP	regs[BPF_REG_FP]
#define AX	regs[BPF_REG_AX]
#define ARG1	regs[BPF_REG_ARG1]
#define CTX	regs[BPF_REG_CTX]
#define IMM	insn->imm

static struct rnd_state __percpu *bpf_user_rnd_state;

static u64 (*interpreters_args[])(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5,
				  const struct bpf_insn *insn);





















struct bpf_prog *bpf_prog_alloc_no_stats(unsigned int size, gfp_t gfp_extra_flags)
{
	gfp_t gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | gfp_extra_flags;
	struct bpf_prog_aux *aux;
	struct bpf_prog *fp;

	size = round_up(size, PAGE_SIZE);
	fp = __vmalloc(size, gfp_flags);
	if (fp == NULL)
		return NULL;

	aux = kzalloc(sizeof(*aux), GFP_KERNEL_ACCOUNT | gfp_extra_flags);
	if (aux == NULL) {
		vfree(fp);
		return NULL;
	}
	fp->active = alloc_percpu_gfp(int, GFP_KERNEL_ACCOUNT | gfp_extra_flags);
	if (!fp->active) {
		vfree(fp);
		kfree(aux);
		return NULL;
	}

	fp->pages = size / PAGE_SIZE;
	fp->aux = aux;
	fp->aux->prog = fp;
	fp->jit_requested = ebpf_jit_enabled();

	INIT_LIST_HEAD_RCU(&fp->aux->ksym.lnode);
	mutex_init(&fp->aux->used_maps_mutex);
	mutex_init(&fp->aux->dst_mutex);

	return fp;
}

struct bpf_prog *bpf_prog_alloc(unsigned int size, gfp_t gfp_extra_flags)
{
	gfp_t gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | gfp_extra_flags;
	struct bpf_prog *prog;
	int cpu;

	prog = bpf_prog_alloc_no_stats(size, gfp_extra_flags);
	if (!prog)
		return NULL;

	prog->stats = alloc_percpu_gfp(struct bpf_prog_stats, gfp_flags);
	if (!prog->stats) {
		free_percpu(prog->active);
		kfree(prog->aux);
		vfree(prog);
		return NULL;
	}

	for_each_possible_cpu(cpu) {
		struct bpf_prog_stats *pstats;

		pstats = per_cpu_ptr(prog->stats, cpu);
		u64_stats_init(&pstats->syncp);
	}
	return prog;
}
EXPORT_SYMBOL_GPL(bpf_prog_alloc);

int bpf_prog_alloc_jited_linfo(struct bpf_prog *prog)
{
	if (!prog->aux->nr_linfo || !prog->jit_requested)
		return 0;

	prog->aux->jited_linfo = kvcalloc(prog->aux->nr_linfo,
					  sizeof(*prog->aux->jited_linfo),
					  GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!prog->aux->jited_linfo)
		return -ENOMEM;

	return 0;
}

void bpf_prog_jit_attempt_done(struct bpf_prog *prog)
{
	if (prog->aux->jited_linfo &&
	    (!prog->jited || !prog->aux->jited_linfo[0])) {
		kvfree(prog->aux->jited_linfo);
		prog->aux->jited_linfo = NULL;
	}





}

























void bpf_prog_fill_jited_linfo(struct bpf_prog *prog,
			       const u32 *insn_to_jit_off)
{
	u32 linfo_idx, insn_start, insn_end, nr_linfo, i;
	const struct bpf_line_info *linfo;
	void **jited_linfo;

	if (!prog->aux->jited_linfo)
		 
		return;

	linfo_idx = prog->aux->linfo_idx;
	linfo = &prog->aux->linfo[linfo_idx];
	insn_start = linfo[0].insn_off;
	insn_end = insn_start + prog->len;

	jited_linfo = &prog->aux->jited_linfo[linfo_idx];
	jited_linfo[0] = prog->bpf_func;

	nr_linfo = prog->aux->nr_linfo - linfo_idx;

	for (i = 1; i < nr_linfo && linfo[i].insn_off < insn_end; i++)
		


		jited_linfo[i] = prog->bpf_func +
			insn_to_jit_off[linfo[i].insn_off - insn_start - 1];
}

struct bpf_prog *bpf_prog_realloc(struct bpf_prog *fp_old, unsigned int size,
				  gfp_t gfp_extra_flags)
{
	gfp_t gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | gfp_extra_flags;
	struct bpf_prog *fp;
	u32 pages;

	size = round_up(size, PAGE_SIZE);
	pages = size / PAGE_SIZE;
	if (pages <= fp_old->pages)
		return fp_old;

	fp = __vmalloc(size, gfp_flags);
	if (fp) {
		memcpy(fp, fp_old, fp_old->pages * PAGE_SIZE);
		fp->pages = pages;
		fp->aux->prog = fp;

		


		fp_old->aux = NULL;
		fp_old->stats = NULL;
		fp_old->active = NULL;
		__bpf_prog_free(fp_old);
	}

	return fp;
}

void __bpf_prog_free(struct bpf_prog *fp)
{
	if (fp->aux) {
		mutex_destroy(&fp->aux->used_maps_mutex);
		mutex_destroy(&fp->aux->dst_mutex);
		
		kfree(fp->aux);
	}
	free_percpu(fp->stats);
	free_percpu(fp->active);
	vfree(fp);
}

int bpf_prog_calc_tag(struct bpf_prog *fp)
{
	const u32 bits_offset = SHA1_BLOCK_SIZE - sizeof(__be64);
	u32 raw_size = bpf_prog_tag_scratch_size(fp);
	u32 digest[SHA1_DIGEST_WORDS];
	u32 ws[SHA1_WORKSPACE_WORDS];
	u32 i, bsize, psize, blocks;
	struct bpf_insn *dst;
	bool was_ld_map;
	u8 *raw, *todo;
	__be32 *result;
	__be64 *bits;

	raw = vmalloc(raw_size);
	if (!raw)
		return -ENOMEM;

	sha1_init(digest);
	memset(ws, 0, sizeof(ws));

	


	dst = (void *)raw;
	for (i = 0, was_ld_map = false; i < fp->len; i++) {
		dst[i] = fp->insnsi[i];
		if (!was_ld_map &&
		    dst[i].code == (BPF_LD | BPF_IMM | BPF_DW) &&
		    (dst[i].src_reg == BPF_PSEUDO_MAP_FD ||
		     dst[i].src_reg == BPF_PSEUDO_MAP_VALUE)) {
			was_ld_map = true;
			dst[i].imm = 0;
		} else if (was_ld_map &&
			   dst[i].code == 0 &&
			   dst[i].dst_reg == 0 &&
			   dst[i].src_reg == 0 &&
			   dst[i].off == 0) {
			was_ld_map = false;
			dst[i].imm = 0;
		} else {
			was_ld_map = false;
		}
	}

	psize = bpf_prog_insn_size(fp);
	memset(&raw[psize], 0, raw_size - psize);
	raw[psize++] = 0x80;

	bsize  = round_up(psize, SHA1_BLOCK_SIZE);
	blocks = bsize / SHA1_BLOCK_SIZE;
	todo   = raw;
	if (bsize - psize >= sizeof(__be64)) {
		bits = (__be64 *)(todo + bsize - sizeof(__be64));
	} else {
		bits = (__be64 *)(todo + bsize + bits_offset);
		blocks++;
	}
	*bits = cpu_to_be64((psize - 1) << 3);

	while (blocks--) {
		sha1_transform(digest, todo, ws);
		todo += SHA1_BLOCK_SIZE;
	}

	result = (__force __be32 *)digest;
	for (i = 0; i < SHA1_DIGEST_WORDS; i++)
		result[i] = cpu_to_be32(digest[i]);
	memcpy(fp->tag, result, sizeof(fp->tag));

	vfree(raw);
	return 0;
}

static int bpf_adj_delta_to_imm(struct bpf_insn *insn, u32 pos, s32 end_old,
				s32 end_new, s32 curr, const bool probe_pass)
{
	const s64 imm_min = S32_MIN, imm_max = S32_MAX;
	s32 delta = end_new - end_old;
	s64 imm = insn->imm;

	if (curr < pos && curr + imm + 1 >= end_old)
		imm += delta;
	else if (curr >= end_new && curr + imm + 1 < end_new)
		imm -= delta;
	if (imm < imm_min || imm > imm_max)
		return -ERANGE;
	if (!probe_pass)
		insn->imm = imm;
	return 0;
}

static int bpf_adj_delta_to_off(struct bpf_insn *insn, u32 pos, s32 end_old,
				s32 end_new, s32 curr, const bool probe_pass)
{
	const s32 off_min = S16_MIN, off_max = S16_MAX;
	s32 delta = end_new - end_old;
	s32 off = insn->off;

	if (curr < pos && curr + off + 1 >= end_old)
		off += delta;
	else if (curr >= end_new && curr + off + 1 < end_new)
		off -= delta;
	if (off < off_min || off > off_max)
		return -ERANGE;
	if (!probe_pass)
		insn->off = off;
	return 0;
}

static int bpf_adj_branches(struct bpf_prog *prog, u32 pos, s32 end_old,
			    s32 end_new, const bool probe_pass)
{
	u32 i, insn_cnt = prog->len + (probe_pass ? end_new - end_old : 0);
	struct bpf_insn *insn = prog->insnsi;
	int ret = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		u8 code;

		



		if (probe_pass && i == pos) {
			i = end_new;
			insn = prog->insnsi + end_old;
		}
		code = insn->code;
		if ((BPF_CLASS(code) != BPF_JMP &&
		     BPF_CLASS(code) != BPF_JMP32) ||
		    BPF_OP(code) == BPF_EXIT)
			continue;
		 
		if (BPF_OP(code) == BPF_CALL) {
			if (insn->src_reg != BPF_PSEUDO_CALL)
				continue;
			ret = bpf_adj_delta_to_imm(insn, pos, end_old,
						   end_new, i, probe_pass);
		} else {
			ret = bpf_adj_delta_to_off(insn, pos, end_old,
						   end_new, i, probe_pass);
		}
		if (ret)
			break;
	}

	return ret;
}

static void bpf_adj_linfo(struct bpf_prog *prog, u32 off, u32 delta)
{
	struct bpf_line_info *linfo;
	u32 i, nr_linfo;

	nr_linfo = prog->aux->nr_linfo;
	if (!nr_linfo || !delta)
		return;

	linfo = prog->aux->linfo;

	for (i = 0; i < nr_linfo; i++)
		if (off < linfo[i].insn_off)
			break;

	 
	for (; i < nr_linfo; i++)
		linfo[i].insn_off += delta;
}

struct bpf_prog *bpf_patch_insn_single(struct bpf_prog *prog, u32 off,
				       const struct bpf_insn *patch, u32 len)
{
	u32 insn_adj_cnt, insn_rest, insn_delta = len - 1;
	const u32 cnt_max = S16_MAX;
	struct bpf_prog *prog_adj;
	int err;

	 
	if (insn_delta == 0) {
		memcpy(prog->insnsi + off, patch, sizeof(*patch));
		return prog;
	}

	insn_adj_cnt = prog->len + insn_delta;

	




	if (insn_adj_cnt > cnt_max &&
	    (err = bpf_adj_branches(prog, off, off + 1, off + len, true)))
		return ERR_PTR(err);

	



	prog_adj = bpf_prog_realloc(prog, bpf_prog_size(insn_adj_cnt),
				    GFP_USER);
	if (!prog_adj)
		return ERR_PTR(-ENOMEM);

	prog_adj->len = insn_adj_cnt;

	







	insn_rest = insn_adj_cnt - off - len;

	memmove(prog_adj->insnsi + off + len, prog_adj->insnsi + off + 1,
		sizeof(*patch) * insn_rest);
	memcpy(prog_adj->insnsi + off, patch, sizeof(*patch) * len);

	



	BUG_ON(bpf_adj_branches(prog_adj, off, off + 1, off + len, false));

	bpf_adj_linfo(prog_adj, off, insn_delta);

	return prog_adj;
}















static void bpf_prog_kallsyms_del_subprogs(struct bpf_prog *fp)
{
	int i;

	for (i = 0; i < fp->aux->func_cnt; i++)
		bpf_prog_kallsyms_del(fp->aux->func[i]);
}

void bpf_prog_kallsyms_del_all(struct bpf_prog *fp)
{
	bpf_prog_kallsyms_del_subprogs(fp);
	bpf_prog_kallsyms_del(fp);
}

#ifdef CONFIG_BPF_JIT
 
int bpf_jit_enable   __read_mostly = IS_BUILTIN(CONFIG_BPF_JIT_DEFAULT_ON);

int bpf_jit_harden   __read_mostly;
long bpf_jit_limit   __read_mostly;

static void
bpf_prog_ksym_set_addr(struct bpf_prog *prog)
{
	const struct bpf_binary_header *hdr = bpf_jit_binary_hdr(prog);
	unsigned long addr = (unsigned long)hdr;

	WARN_ON_ONCE(!bpf_prog_ebpf_jited(prog));

	prog->aux->ksym.start = (unsigned long) prog->bpf_func;
	prog->aux->ksym.end   = addr + hdr->pages * PAGE_SIZE;
}

static void
bpf_prog_ksym_set_name(struct bpf_prog *prog)
{
	char *sym = prog->aux->ksym.name;
	const char *end = sym + KSYM_NAME_LEN;
	const struct btf_type *type;
	const char *func_name;

	BUILD_BUG_ON(sizeof("bpf_prog_") +
		     sizeof(prog->tag) * 2 +
		     






		     sizeof(prog->aux->name) > KSYM_NAME_LEN);

	sym += snprintf(sym, KSYM_NAME_LEN, "bpf_prog_");
	sym  = bin2hex(sym, prog->tag, sizeof(prog->tag));

	 
	if (prog->aux->func_info_cnt) {
		type = btf_type_by_id(prog->aux->btf,
				      prog->aux->func_info[prog->aux->func_idx].type_id);
		func_name = btf_name_by_offset(prog->aux->btf, type->name_off);
		snprintf(sym, (size_t)(end - sym), "_%s", func_name);
		return;
	}

	if (prog->aux->name[0])
		snprintf(sym, (size_t)(end - sym), "_%s", prog->aux->name);
	else
		*sym = 0;
}

static unsigned long bpf_get_ksym_start(struct latch_tree_node *n)
{
	return container_of(n, struct bpf_ksym, tnode)->start;
}

static __always_inline bool bpf_tree_less(struct latch_tree_node *a,
					  struct latch_tree_node *b)
{
	return bpf_get_ksym_start(a) < bpf_get_ksym_start(b);
}

static __always_inline int bpf_tree_comp(void *key, struct latch_tree_node *n)
{
	unsigned long val = (unsigned long)key;
	const struct bpf_ksym *ksym;

	ksym = container_of(n, struct bpf_ksym, tnode);

	if (val < ksym->start)
		return -1;
	if (val >= ksym->end)
		return  1;

	return 0;
}

static const struct latch_tree_ops bpf_tree_ops = {
	.less	= bpf_tree_less,
	.comp	= bpf_tree_comp,
};

static DEFINE_SPINLOCK(bpf_lock);
static LIST_HEAD(bpf_kallsyms);
static struct latch_tree_root bpf_tree __cacheline_aligned;

void bpf_ksym_add(struct bpf_ksym *ksym)
{
	spin_lock_bh(&bpf_lock);
	WARN_ON_ONCE(!list_empty(&ksym->lnode));
	list_add_tail_rcu(&ksym->lnode, &bpf_kallsyms);
	latch_tree_insert(&ksym->tnode, &bpf_tree, &bpf_tree_ops);
	spin_unlock_bh(&bpf_lock);
}

static void __bpf_ksym_del(struct bpf_ksym *ksym)
{
	if (list_empty(&ksym->lnode))
		return;

	latch_tree_erase(&ksym->tnode, &bpf_tree, &bpf_tree_ops);
	list_del_rcu(&ksym->lnode);
}

void bpf_ksym_del(struct bpf_ksym *ksym)
{
	spin_lock_bh(&bpf_lock);
	__bpf_ksym_del(ksym);
	spin_unlock_bh(&bpf_lock);
}

static bool bpf_prog_kallsyms_candidate(const struct bpf_prog *fp)
{
	return fp->jited && !bpf_prog_was_classic(fp);
}

static bool bpf_prog_kallsyms_verify_off(const struct bpf_prog *fp)
{
	return list_empty(&fp->aux->ksym.lnode) ||
	       fp->aux->ksym.lnode.prev == LIST_POISON2;
}

void bpf_prog_kallsyms_add(struct bpf_prog *fp)
{
	if (!bpf_prog_kallsyms_candidate(fp) ||
	    !bpf_capable())
		return;

	bpf_prog_ksym_set_addr(fp);
	bpf_prog_ksym_set_name(fp);
	fp->aux->ksym.prog = true;

	bpf_ksym_add(&fp->aux->ksym);
}

void bpf_prog_kallsyms_del(struct bpf_prog *fp)
{
	if (!bpf_prog_kallsyms_candidate(fp))
		return;

	bpf_ksym_del(&fp->aux->ksym);
}

static struct bpf_ksym *bpf_ksym_find(unsigned long addr)
{
	struct latch_tree_node *n;

	n = latch_tree_find((void *)addr, &bpf_tree, &bpf_tree_ops);
	return n ? container_of(n, struct bpf_ksym, tnode) : NULL;
}




























bool is_bpf_text_address(unsigned long addr)
{
	bool ret;

	rcu_read_lock();
	ret = bpf_ksym_find(addr) != NULL;
	rcu_read_unlock();

	return ret;
}


























































int bpf_jit_add_poke_descriptor(struct bpf_prog *prog,
				struct bpf_jit_poke_descriptor *poke)
{
	struct bpf_jit_poke_descriptor *tab = prog->aux->poke_tab;
	static const u32 poke_tab_max = 1024;
	u32 slot = prog->aux->size_poke_tab;
	u32 size = slot + 1;

	if (size > poke_tab_max)
		return -ENOSPC;
	if (poke->tailcall_target || poke->tailcall_target_stable ||
	    poke->tailcall_bypass || poke->adj_off || poke->bypass_addr)
		return -EINVAL;

	switch (poke->reason) {
	case BPF_POKE_REASON_TAIL_CALL:
		if (!poke->tail_call.map)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	tab = krealloc(tab, size * sizeof(*poke), GFP_KERNEL);
	if (!tab)
		return -ENOMEM;

	memcpy(&tab[slot], poke, sizeof(*poke));
	prog->aux->size_poke_tab = size;
	prog->aux->poke_tab = tab;

	return slot;
}

static atomic_long_t bpf_jit_current;





u64 __weak bpf_jit_alloc_exec_limit(void)
{
#if defined(MODULES_VADDR)
	return MODULES_END - MODULES_VADDR;
#else
	return VMALLOC_END - VMALLOC_START;
#endif
}

int bpf_jit_charge_init0(void)
{
	 
	bpf_jit_limit = min_t(u64, round_up(bpf_jit_alloc_exec_limit() >> 2,
					    PAGE_SIZE), LONG_MAX);
	return 0;
}

int bpf_jit_charge_modmem(u32 pages)
{
	if (atomic_long_add_return(pages, &bpf_jit_current) >
	    (bpf_jit_limit >> PAGE_SHIFT)) {
		if (!capable(CAP_SYS_ADMIN)) {
			atomic_long_sub(pages, &bpf_jit_current);
			return -EPERM;
		}
	}

	return 0;
}

void bpf_jit_uncharge_modmem(u32 pages)
{
	atomic_long_sub(pages, &bpf_jit_current);
}

void *__weak bpf_jit_alloc_exec(unsigned long size)
{
	return module_alloc(size);
}

void __weak bpf_jit_free_exec(void *addr)
{
	module_memfree(addr);
}

struct bpf_binary_header *
bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		     unsigned int alignment,
		     bpf_jit_fill_hole_t bpf_fill_ill_insns)
{
	struct bpf_binary_header *hdr;
	u32 size, hole, start, pages;

	WARN_ON_ONCE(!is_power_of_2(alignment) ||
		     alignment > BPF_IMAGE_ALIGNMENT);

	



	size = round_up(proglen + sizeof(*hdr) + 128, PAGE_SIZE);
	pages = size / PAGE_SIZE;

	if (bpf_jit_charge_modmem(pages))
		return NULL;
	hdr = bpf_jit_alloc_exec(size);
	if (!hdr) {
		bpf_jit_uncharge_modmem(pages);
		return NULL;
	}

	 
	bpf_fill_ill_insns(hdr, size);

	hdr->pages = pages;
	hole = min_t(unsigned int, size - (proglen + sizeof(*hdr)),
		     PAGE_SIZE - sizeof(*hdr));
	start = (get_random_int() % hole) & ~(alignment - 1);

	 
	*image_ptr = &hdr->image[start];

	return hdr;
}

void bpf_jit_binary_free(struct bpf_binary_header *hdr)
{
	u32 pages = hdr->pages;

	bpf_jit_free_exec(hdr);
	bpf_jit_uncharge_modmem(pages);
}





void __weak bpf_jit_free(struct bpf_prog *fp)
{
	if (fp->jited) {
		struct bpf_binary_header *hdr = bpf_jit_binary_hdr(fp);

		bpf_jit_binary_unlock_ro(hdr);
		bpf_jit_binary_free(hdr);

		WARN_ON_ONCE(!bpf_prog_kallsyms_verify_off(fp));
	}

	bpf_prog_unlock_free(fp);
}

int bpf_jit_get_func_addr(const struct bpf_prog *prog,
			  const struct bpf_insn *insn, bool extra_pass,
			  u64 *func_addr, bool *func_addr_fixed)
{
	s16 off = insn->off;
	s32 imm = insn->imm;
	u8 *addr;

	*func_addr_fixed = insn->src_reg != BPF_PSEUDO_CALL;
	if (!*func_addr_fixed) {
		



		if (!extra_pass)
			addr = NULL;
		else if (prog->aux->func &&
			 off >= 0 && off < prog->aux->func_cnt)
			addr = (u8 *)prog->aux->func[off]->bpf_func;
		else
			return -EINVAL;
	} else {
		




		addr = (u8 *)__bpf_call_base + imm;
	}

	*func_addr = (unsigned long)addr;
	return 0;
}

static int bpf_jit_blind_insn(const struct bpf_insn *from,
			      const struct bpf_insn *aux,
			      struct bpf_insn *to_buff,
			      bool emit_zext)
{
	struct bpf_insn *to = to_buff;
	u32 imm_rnd = get_random_int();
	s16 off;

	BUILD_BUG_ON(BPF_REG_AX  + 1 != MAX_BPF_JIT_REG);
	BUILD_BUG_ON(MAX_BPF_REG + 1 != MAX_BPF_JIT_REG);

	
















	if (from->dst_reg == BPF_REG_AX || from->src_reg == BPF_REG_AX)
		goto out;

	if (from->imm == 0 &&
	    (from->code == (BPF_ALU   | BPF_MOV | BPF_K) ||
	     from->code == (BPF_ALU64 | BPF_MOV | BPF_K))) {
		*to++ = BPF_ALU64_REG(BPF_XOR, from->dst_reg, from->dst_reg);
		goto out;
	}

	switch (from->code) {
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_OR  | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_K:
		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_ALU32_REG(from->code, from->dst_reg, BPF_REG_AX);
		break;

	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_OR  | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_ALU64_REG(from->code, from->dst_reg, BPF_REG_AX);
		break;

	case BPF_JMP | BPF_JEQ  | BPF_K:
	case BPF_JMP | BPF_JNE  | BPF_K:
	case BPF_JMP | BPF_JGT  | BPF_K:
	case BPF_JMP | BPF_JLT  | BPF_K:
	case BPF_JMP | BPF_JGE  | BPF_K:
	case BPF_JMP | BPF_JLE  | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
		 
		off = from->off;
		if (off < 0)
			off -= 2;
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_JMP_REG(from->code, from->dst_reg, BPF_REG_AX, off);
		break;

	case BPF_JMP32 | BPF_JEQ  | BPF_K:
	case BPF_JMP32 | BPF_JNE  | BPF_K:
	case BPF_JMP32 | BPF_JGT  | BPF_K:
	case BPF_JMP32 | BPF_JLT  | BPF_K:
	case BPF_JMP32 | BPF_JGE  | BPF_K:
	case BPF_JMP32 | BPF_JLE  | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
		 
		off = from->off;
		if (off < 0)
			off -= 2;
		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_JMP32_REG(from->code, from->dst_reg, BPF_REG_AX,
				      off);
		break;

	case BPF_LD | BPF_IMM | BPF_DW:
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ aux[1].imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_ALU64_IMM(BPF_LSH, BPF_REG_AX, 32);
		*to++ = BPF_ALU64_REG(BPF_MOV, aux[0].dst_reg, BPF_REG_AX);
		break;
	case 0:  
		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ aux[0].imm);
		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		if (emit_zext)
			*to++ = BPF_ZEXT_REG(BPF_REG_AX);
		*to++ = BPF_ALU64_REG(BPF_OR,  aux[0].dst_reg, BPF_REG_AX);
		break;

	case BPF_ST | BPF_MEM | BPF_DW:
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_STX_MEM(from->code, from->dst_reg, BPF_REG_AX, from->off);
		break;
	}
out:
	return to - to_buff;
}

static struct bpf_prog *bpf_prog_clone_create(struct bpf_prog *fp_other,
					      gfp_t gfp_extra_flags)
{
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO | gfp_extra_flags;
	struct bpf_prog *fp;

	fp = __vmalloc(fp_other->pages * PAGE_SIZE, gfp_flags);
	if (fp != NULL) {
		



		memcpy(fp, fp_other, fp_other->pages * PAGE_SIZE);
	}

	return fp;
}

static void bpf_prog_clone_free(struct bpf_prog *fp)
{
	






	fp->aux = NULL;
	fp->stats = NULL;
	fp->active = NULL;
	__bpf_prog_free(fp);
}

void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other)
{
	


	fp->aux->prog = fp;
	bpf_prog_clone_free(fp_other);
}

struct bpf_prog *bpf_jit_blind_constants(struct bpf_prog *prog)
{
	struct bpf_insn insn_buff[16], aux[2];
	struct bpf_prog *clone, *tmp;
	int insn_delta, insn_cnt;
	struct bpf_insn *insn;
	int i, rewritten;

	if (!bpf_jit_blinding_enabled(prog) || prog->blinded)
		return prog;

	clone = bpf_prog_clone_create(prog, GFP_USER);
	if (!clone)
		return ERR_PTR(-ENOMEM);

	insn_cnt = clone->len;
	insn = clone->insnsi;

	for (i = 0; i < insn_cnt; i++, insn++) {
		



		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW) &&
		    insn[1].code == 0)
			memcpy(aux, insn, sizeof(aux));

		rewritten = bpf_jit_blind_insn(insn, aux, insn_buff,
						clone->aux->verifier_zext);
		if (!rewritten)
			continue;

		tmp = bpf_patch_insn_single(clone, i, insn_buff, rewritten);
		if (IS_ERR(tmp)) {
			



			bpf_jit_prog_release_other(prog, clone);
			return tmp;
		}

		clone = tmp;
		insn_delta = rewritten - 1;

		 
		insn = clone->insnsi + i + insn_delta;
		insn_cnt += insn_delta;
		i        += insn_delta;
	}

	clone->blinded = 1;
	return clone;
}
#endif  







noinline u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return 0;
}
EXPORT_SYMBOL_GPL(__bpf_call_base);

 
#define BPF_INSN_MAP(INSN_2, INSN_3)		\
	 		\
	 			\
	INSN_3(ALU, ADD,  X),			\
	INSN_3(ALU, SUB,  X),			\
	INSN_3(ALU, AND,  X),			\
	INSN_3(ALU, OR,   X),			\
	INSN_3(ALU, LSH,  X),			\
	INSN_3(ALU, RSH,  X),			\
	INSN_3(ALU, XOR,  X),			\
	INSN_3(ALU, MUL,  X),			\
	INSN_3(ALU, MOV,  X),			\
	INSN_3(ALU, ARSH, X),			\
	INSN_3(ALU, DIV,  X),			\
	INSN_3(ALU, MOD,  X),			\
	INSN_2(ALU, NEG),			\
	INSN_3(ALU, END, TO_BE),		\
	INSN_3(ALU, END, TO_LE),		\
	 		\
	INSN_3(ALU, ADD,  K),			\
	INSN_3(ALU, SUB,  K),			\
	INSN_3(ALU, AND,  K),			\
	INSN_3(ALU, OR,   K),			\
	INSN_3(ALU, LSH,  K),			\
	INSN_3(ALU, RSH,  K),			\
	INSN_3(ALU, XOR,  K),			\
	INSN_3(ALU, MUL,  K),			\
	INSN_3(ALU, MOV,  K),			\
	INSN_3(ALU, ARSH, K),			\
	INSN_3(ALU, DIV,  K),			\
	INSN_3(ALU, MOD,  K),			\
	 		\
	 			\
	INSN_3(ALU64, ADD,  X),			\
	INSN_3(ALU64, SUB,  X),			\
	INSN_3(ALU64, AND,  X),			\
	INSN_3(ALU64, OR,   X),			\
	INSN_3(ALU64, LSH,  X),			\
	INSN_3(ALU64, RSH,  X),			\
	INSN_3(ALU64, XOR,  X),			\
	INSN_3(ALU64, MUL,  X),			\
	INSN_3(ALU64, MOV,  X),			\
	INSN_3(ALU64, ARSH, X),			\
	INSN_3(ALU64, DIV,  X),			\
	INSN_3(ALU64, MOD,  X),			\
	INSN_2(ALU64, NEG),			\
	 		\
	INSN_3(ALU64, ADD,  K),			\
	INSN_3(ALU64, SUB,  K),			\
	INSN_3(ALU64, AND,  K),			\
	INSN_3(ALU64, OR,   K),			\
	INSN_3(ALU64, LSH,  K),			\
	INSN_3(ALU64, RSH,  K),			\
	INSN_3(ALU64, XOR,  K),			\
	INSN_3(ALU64, MUL,  K),			\
	INSN_3(ALU64, MOV,  K),			\
	INSN_3(ALU64, ARSH, K),			\
	INSN_3(ALU64, DIV,  K),			\
	INSN_3(ALU64, MOD,  K),			\
	 			\
	INSN_2(JMP, CALL),			\
	 			\
	INSN_2(JMP, EXIT),			\
	 		\
	 			\
	INSN_3(JMP32, JEQ,  X),			\
	INSN_3(JMP32, JNE,  X),			\
	INSN_3(JMP32, JGT,  X),			\
	INSN_3(JMP32, JLT,  X),			\
	INSN_3(JMP32, JGE,  X),			\
	INSN_3(JMP32, JLE,  X),			\
	INSN_3(JMP32, JSGT, X),			\
	INSN_3(JMP32, JSLT, X),			\
	INSN_3(JMP32, JSGE, X),			\
	INSN_3(JMP32, JSLE, X),			\
	INSN_3(JMP32, JSET, X),			\
	 		\
	INSN_3(JMP32, JEQ,  K),			\
	INSN_3(JMP32, JNE,  K),			\
	INSN_3(JMP32, JGT,  K),			\
	INSN_3(JMP32, JLT,  K),			\
	INSN_3(JMP32, JGE,  K),			\
	INSN_3(JMP32, JLE,  K),			\
	INSN_3(JMP32, JSGT, K),			\
	INSN_3(JMP32, JSLT, K),			\
	INSN_3(JMP32, JSGE, K),			\
	INSN_3(JMP32, JSLE, K),			\
	INSN_3(JMP32, JSET, K),			\
	 		\
	 			\
	INSN_3(JMP, JEQ,  X),			\
	INSN_3(JMP, JNE,  X),			\
	INSN_3(JMP, JGT,  X),			\
	INSN_3(JMP, JLT,  X),			\
	INSN_3(JMP, JGE,  X),			\
	INSN_3(JMP, JLE,  X),			\
	INSN_3(JMP, JSGT, X),			\
	INSN_3(JMP, JSLT, X),			\
	INSN_3(JMP, JSGE, X),			\
	INSN_3(JMP, JSLE, X),			\
	INSN_3(JMP, JSET, X),			\
	 		\
	INSN_3(JMP, JEQ,  K),			\
	INSN_3(JMP, JNE,  K),			\
	INSN_3(JMP, JGT,  K),			\
	INSN_3(JMP, JLT,  K),			\
	INSN_3(JMP, JGE,  K),			\
	INSN_3(JMP, JLE,  K),			\
	INSN_3(JMP, JSGT, K),			\
	INSN_3(JMP, JSLT, K),			\
	INSN_3(JMP, JSGE, K),			\
	INSN_3(JMP, JSLE, K),			\
	INSN_3(JMP, JSET, K),			\
	INSN_2(JMP, JA),			\
	 		\
	 			\
	INSN_3(STX, MEM,  B),			\
	INSN_3(STX, MEM,  H),			\
	INSN_3(STX, MEM,  W),			\
	INSN_3(STX, MEM,  DW),			\
	INSN_3(STX, ATOMIC, W),			\
	INSN_3(STX, ATOMIC, DW),		\
	 		\
	INSN_3(ST, MEM, B),			\
	INSN_3(ST, MEM, H),			\
	INSN_3(ST, MEM, W),			\
	INSN_3(ST, MEM, DW),			\
	 		\
	 			\
	INSN_3(LDX, MEM, B),			\
	INSN_3(LDX, MEM, H),			\
	INSN_3(LDX, MEM, W),			\
	INSN_3(LDX, MEM, DW),			\
	 		\
	INSN_3(LD, IMM, DW)

bool bpf_opcode_in_insntable(u8 code)
{
#define BPF_INSN_2_TBL(x, y)    [BPF_##x | BPF_##y] = true
#define BPF_INSN_3_TBL(x, y, z) [BPF_##x | BPF_##y | BPF_##z] = true
	static const bool public_insntable[256] = {
		[0 ... 255] = false,
		 
		BPF_INSN_MAP(BPF_INSN_2_TBL, BPF_INSN_3_TBL),
		 
		[BPF_LD | BPF_ABS | BPF_B] = true,
		[BPF_LD | BPF_ABS | BPF_H] = true,
		[BPF_LD | BPF_ABS | BPF_W] = true,
		[BPF_LD | BPF_IND | BPF_B] = true,
		[BPF_LD | BPF_IND | BPF_H] = true,
		[BPF_LD | BPF_IND | BPF_W] = true,
	};
#undef BPF_INSN_3_TBL
#undef BPF_INSN_2_TBL
	return public_insntable[code];
}

#ifndef CONFIG_BPF_JIT_ALWAYS_ON
u64 __weak bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)
{
	memset(dst, 0, size);
	return -EFAULT;
}








static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
{
#define BPF_INSN_2_LBL(x, y)    [BPF_##x | BPF_##y] = &&x##_##y
#define BPF_INSN_3_LBL(x, y, z) [BPF_##x | BPF_##y | BPF_##z] = &&x##_##y##_##z
	static const void * const jumptable[256] __annotate_jump_table = {
		[0 ... 255] = &&default_label,
		 
		BPF_INSN_MAP(BPF_INSN_2_LBL, BPF_INSN_3_LBL),
		 
		[BPF_JMP | BPF_CALL_ARGS] = &&JMP_CALL_ARGS,
		[BPF_JMP | BPF_TAIL_CALL] = &&JMP_TAIL_CALL,
		[BPF_ST  | BPF_NOSPEC] = &&ST_NOSPEC,
		[BPF_LDX | BPF_PROBE_MEM | BPF_B] = &&LDX_PROBE_MEM_B,
		[BPF_LDX | BPF_PROBE_MEM | BPF_H] = &&LDX_PROBE_MEM_H,
		[BPF_LDX | BPF_PROBE_MEM | BPF_W] = &&LDX_PROBE_MEM_W,
		[BPF_LDX | BPF_PROBE_MEM | BPF_DW] = &&LDX_PROBE_MEM_DW,
	};
#undef BPF_INSN_3_LBL
#undef BPF_INSN_2_LBL
	u32 tail_call_cnt = 0;

#define CONT	 ({ insn++; goto select_insn; })
#define CONT_JMP ({ insn++; goto select_insn; })

select_insn:
	goto *jumptable[insn->code];

	










	 
#define SHT(OPCODE, OP)					\
	ALU64_##OPCODE##_X:				\
		DST = DST OP (SRC & 63);		\
		CONT;					\
	ALU_##OPCODE##_X:				\
		DST = (u32) DST OP ((u32) SRC & 31);	\
		CONT;					\
	ALU64_##OPCODE##_K:				\
		DST = DST OP IMM;			\
		CONT;					\
	ALU_##OPCODE##_K:				\
		DST = (u32) DST OP (u32) IMM;		\
		CONT;
	 
#define ALU(OPCODE, OP)					\
	ALU64_##OPCODE##_X:				\
		DST = DST OP SRC;			\
		CONT;					\
	ALU_##OPCODE##_X:				\
		DST = (u32) DST OP (u32) SRC;		\
		CONT;					\
	ALU64_##OPCODE##_K:				\
		DST = DST OP IMM;			\
		CONT;					\
	ALU_##OPCODE##_K:				\
		DST = (u32) DST OP (u32) IMM;		\
		CONT;
	ALU(ADD,  +)
	ALU(SUB,  -)
	ALU(AND,  &)
	ALU(OR,   |)
	ALU(XOR,  ^)
	ALU(MUL,  *)
	SHT(LSH, <<)
	SHT(RSH, >>)
#undef SHT
#undef ALU
	ALU_NEG:
		DST = (u32) -DST;
		CONT;
	ALU64_NEG:
		DST = -DST;
		CONT;
	ALU_MOV_X:
		DST = (u32) SRC;
		CONT;
	ALU_MOV_K:
		DST = (u32) IMM;
		CONT;
	ALU64_MOV_X:
		DST = SRC;
		CONT;
	ALU64_MOV_K:
		DST = IMM;
		CONT;
	LD_IMM_DW:
		DST = (u64) (u32) insn[0].imm | ((u64) (u32) insn[1].imm) << 32;
		insn++;
		CONT;
	ALU_ARSH_X:
		DST = (u64) (u32) (((s32) DST) >> (SRC & 31));
		CONT;
	ALU_ARSH_K:
		DST = (u64) (u32) (((s32) DST) >> IMM);
		CONT;
	ALU64_ARSH_X:
		(*(s64 *) &DST) >>= (SRC & 63);
		CONT;
	ALU64_ARSH_K:
		(*(s64 *) &DST) >>= IMM;
		CONT;
	ALU64_MOD_X:
		div64_u64_rem(DST, SRC, &AX);
		DST = AX;
		CONT;
	ALU_MOD_X:
		AX = (u32) DST;
		DST = do_div(AX, (u32) SRC);
		CONT;
	ALU64_MOD_K:
		div64_u64_rem(DST, IMM, &AX);
		DST = AX;
		CONT;
	ALU_MOD_K:
		AX = (u32) DST;
		DST = do_div(AX, (u32) IMM);
		CONT;
	ALU64_DIV_X:
		DST = div64_u64(DST, SRC);
		CONT;
	ALU_DIV_X:
		AX = (u32) DST;
		do_div(AX, (u32) SRC);
		DST = (u32) AX;
		CONT;
	ALU64_DIV_K:
		DST = div64_u64(DST, IMM);
		CONT;
	ALU_DIV_K:
		AX = (u32) DST;
		do_div(AX, (u32) IMM);
		DST = (u32) AX;
		CONT;
	ALU_END_TO_BE:
		switch (IMM) {
		case 16:
			DST = (__force u16) cpu_to_be16(DST);
			break;
		case 32:
			DST = (__force u32) cpu_to_be32(DST);
			break;
		case 64:
			DST = (__force u64) cpu_to_be64(DST);
			break;
		}
		CONT;
	ALU_END_TO_LE:
		switch (IMM) {
		case 16:
			DST = (__force u16) cpu_to_le16(DST);
			break;
		case 32:
			DST = (__force u32) cpu_to_le32(DST);
			break;
		case 64:
			DST = (__force u64) cpu_to_le64(DST);
			break;
		}
		CONT;

	 
	JMP_CALL:
		



		BPF_R0 = (__bpf_call_base + insn->imm)(BPF_R1, BPF_R2, BPF_R3,
						       BPF_R4, BPF_R5);
		CONT;

	JMP_CALL_ARGS:
		BPF_R0 = (interpreters_args[insn->off])(BPF_R1, BPF_R2,
							    BPF_R3, BPF_R4,
							    BPF_R5,
							    insn + insn->imm + 1);
		CONT;

	JMP_TAIL_CALL: {
		struct bpf_map *map = (struct bpf_map *) (unsigned long) BPF_R2;
		struct bpf_array *array = container_of(map, struct bpf_array, map);
		struct bpf_prog *prog;
		u32 index = BPF_R3;

		if (unlikely(index >= array->map.max_entries))
			goto out;
		if (unlikely(tail_call_cnt > MAX_TAIL_CALL_CNT))
			goto out;

		tail_call_cnt++;

		prog = READ_ONCE(array->ptrs[index]);
		if (!prog)
			goto out;

		




		insn = prog->insnsi;
		goto select_insn;
out:
		CONT;
	}
	JMP_JA:
		insn += insn->off;
		CONT;
	JMP_EXIT:
		return BPF_R0;
	 
#define COND_JMP(SIGN, OPCODE, CMP_OP)				\
	JMP_##OPCODE##_X:					\
		if ((SIGN##64) DST CMP_OP (SIGN##64) SRC) {	\
			insn += insn->off;			\
			CONT_JMP;				\
		}						\
		CONT;						\
	JMP32_##OPCODE##_X:					\
		if ((SIGN##32) DST CMP_OP (SIGN##32) SRC) {	\
			insn += insn->off;			\
			CONT_JMP;				\
		}						\
		CONT;						\
	JMP_##OPCODE##_K:					\
		if ((SIGN##64) DST CMP_OP (SIGN##64) IMM) {	\
			insn += insn->off;			\
			CONT_JMP;				\
		}						\
		CONT;						\
	JMP32_##OPCODE##_K:					\
		if ((SIGN##32) DST CMP_OP (SIGN##32) IMM) {	\
			insn += insn->off;			\
			CONT_JMP;				\
		}						\
		CONT;
	COND_JMP(u, JEQ, ==)
	COND_JMP(u, JNE, !=)
	COND_JMP(u, JGT, >)
	COND_JMP(u, JLT, <)
	COND_JMP(u, JGE, >=)
	COND_JMP(u, JLE, <=)
	COND_JMP(u, JSET, &)
	COND_JMP(s, JSGT, >)
	COND_JMP(s, JSLT, <)
	COND_JMP(s, JSGE, >=)
	COND_JMP(s, JSLE, <=)
#undef COND_JMP
	 
	ST_NOSPEC:
		








#ifdef CONFIG_X86
		barrier_nospec();
#endif
		CONT;
#define LDST(SIZEOP, SIZE)						\
	STX_MEM_##SIZEOP:						\
		*(SIZE *)(unsigned long) (DST + insn->off) = SRC;	\
		CONT;							\
	ST_MEM_##SIZEOP:						\
		*(SIZE *)(unsigned long) (DST + insn->off) = IMM;	\
		CONT;							\
	LDX_MEM_##SIZEOP:						\
		DST = *(SIZE *)(unsigned long) (SRC + insn->off);	\
		CONT;

	LDST(B,   u8)
	LDST(H,  u16)
	LDST(W,  u32)
	LDST(DW, u64)
#undef LDST
#define LDX_PROBE(SIZEOP, SIZE)							\
	LDX_PROBE_MEM_##SIZEOP:							\
		bpf_probe_read_kernel(&DST, SIZE, (const void *)(long) (SRC + insn->off));	\
		CONT;
	LDX_PROBE(B,  1)
	LDX_PROBE(H,  2)
	LDX_PROBE(W,  4)
	LDX_PROBE(DW, 8)
#undef LDX_PROBE

#define ATOMIC_ALU_OP(BOP, KOP)						\
		case BOP:						\
			if (BPF_SIZE(insn->code) == BPF_W)		\
				atomic_##KOP((u32) SRC, (atomic_t *)(unsigned long) \
					     (DST + insn->off));	\
			else						\
				atomic64_##KOP((u64) SRC, (atomic64_t *)(unsigned long) \
					       (DST + insn->off));	\
			break;						\
		case BOP | BPF_FETCH:					\
			if (BPF_SIZE(insn->code) == BPF_W)		\
				SRC = (u32) atomic_fetch_##KOP(		\
					(u32) SRC,			\
					(atomic_t *)(unsigned long) (DST + insn->off)); \
			else						\
				SRC = (u64) atomic64_fetch_##KOP(	\
					(u64) SRC,			\
					(atomic64_t *)(unsigned long) (DST + insn->off)); \
			break;

	STX_ATOMIC_DW:
	STX_ATOMIC_W:
		switch (IMM) {
		ATOMIC_ALU_OP(BPF_ADD, add)
		ATOMIC_ALU_OP(BPF_AND, and)
		ATOMIC_ALU_OP(BPF_OR, or)
		ATOMIC_ALU_OP(BPF_XOR, xor)
#undef ATOMIC_ALU_OP

		case BPF_XCHG:
			if (BPF_SIZE(insn->code) == BPF_W)
				SRC = (u32) atomic_xchg(
					(atomic_t *)(unsigned long) (DST + insn->off),
					(u32) SRC);
			else
				SRC = (u64) atomic64_xchg(
					(atomic64_t *)(unsigned long) (DST + insn->off),
					(u64) SRC);
			break;
		case BPF_CMPXCHG:
			if (BPF_SIZE(insn->code) == BPF_W)
				BPF_R0 = (u32) atomic_cmpxchg(
					(atomic_t *)(unsigned long) (DST + insn->off),
					(u32) BPF_R0, (u32) SRC);
			else
				BPF_R0 = (u64) atomic64_cmpxchg(
					(atomic64_t *)(unsigned long) (DST + insn->off),
					(u64) BPF_R0, (u64) SRC);
			break;

		default:
			goto default_label;
		}
		CONT;

	default_label:
		





		pr_warn("BPF interpreter: unknown opcode %02x (imm: 0x%x)\n",
			insn->code, insn->imm);
		BUG_ON(1);
		return 0;
}

#define PROG_NAME(stack_size) __bpf_prog_run##stack_size
#define DEFINE_BPF_PROG_RUN(stack_size) \
static unsigned int PROG_NAME(stack_size)(const void *ctx, const struct bpf_insn *insn) \
{ \
	u64 stack[stack_size / sizeof(u64)]; \
	u64 regs[MAX_BPF_EXT_REG]; \
\
	FP = (u64) (unsigned long) &stack[ARRAY_SIZE(stack)]; \
	ARG1 = (u64) (unsigned long) ctx; \
	return ___bpf_prog_run(regs, insn); \
}

#define PROG_NAME_ARGS(stack_size) __bpf_prog_run_args##stack_size
#define DEFINE_BPF_PROG_RUN_ARGS(stack_size) \
static u64 PROG_NAME_ARGS(stack_size)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5, \
				      const struct bpf_insn *insn) \
{ \
	u64 stack[stack_size / sizeof(u64)]; \
	u64 regs[MAX_BPF_EXT_REG]; \
\
	FP = (u64) (unsigned long) &stack[ARRAY_SIZE(stack)]; \
	BPF_R1 = r1; \
	BPF_R2 = r2; \
	BPF_R3 = r3; \
	BPF_R4 = r4; \
	BPF_R5 = r5; \
	return ___bpf_prog_run(regs, insn); \
}

#define EVAL1(FN, X) FN(X)
#define EVAL2(FN, X, Y...) FN(X) EVAL1(FN, Y)
#define EVAL3(FN, X, Y...) FN(X) EVAL2(FN, Y)
#define EVAL4(FN, X, Y...) FN(X) EVAL3(FN, Y)
#define EVAL5(FN, X, Y...) FN(X) EVAL4(FN, Y)
#define EVAL6(FN, X, Y...) FN(X) EVAL5(FN, Y)

EVAL6(DEFINE_BPF_PROG_RUN, 32, 64, 96, 128, 160, 192);
EVAL6(DEFINE_BPF_PROG_RUN, 224, 256, 288, 320, 352, 384);
EVAL6(DEFINE_BPF_PROG_RUN, 416, 448, 480, 512, 544, 576);
EVAL2(DEFINE_BPF_PROG_RUN, 608, 640);

EVAL6(DEFINE_BPF_PROG_RUN_ARGS, 32, 64, 96, 128, 160, 192);
EVAL6(DEFINE_BPF_PROG_RUN_ARGS, 224, 256, 288, 320, 352, 384);
EVAL6(DEFINE_BPF_PROG_RUN_ARGS, 416, 448, 480, 512, 544, 576);
EVAL2(DEFINE_BPF_PROG_RUN_ARGS, 608, 640);

#define PROG_NAME_LIST(stack_size) PROG_NAME(stack_size),

static unsigned int (*interpreters[])(const void *ctx,
				      const struct bpf_insn *insn) = {
EVAL6(PROG_NAME_LIST, 32, 64, 96, 128, 160, 192)
EVAL6(PROG_NAME_LIST, 224, 256, 288, 320, 352, 384)
EVAL6(PROG_NAME_LIST, 416, 448, 480, 512, 544, 576)
EVAL2(PROG_NAME_LIST, 608, 640)
};
#undef PROG_NAME_LIST
#define PROG_NAME_LIST(stack_size) PROG_NAME_ARGS(stack_size),
static u64 (*interpreters_args[])(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5,
				  const struct bpf_insn *insn) = {
EVAL6(PROG_NAME_LIST, 32, 64, 96, 128, 160, 192)
EVAL6(PROG_NAME_LIST, 224, 256, 288, 320, 352, 384)
EVAL6(PROG_NAME_LIST, 416, 448, 480, 512, 544, 576)
EVAL2(PROG_NAME_LIST, 608, 640)
};
#undef PROG_NAME_LIST

void bpf_patch_call_args(struct bpf_insn *insn, u32 stack_depth)
{
	stack_depth = max_t(u32, stack_depth, 1);





#if 1
	insn->off = (round_up(stack_depth, 32) / 32) - 1;
#endif
	dd("bpf call base args off: %d", insn->imm);
	insn->code = BPF_JMP | BPF_CALL_ARGS;
}

#else
static unsigned int __bpf_prog_ret0_warn(const void *ctx,
					 const struct bpf_insn *insn)
{
	


	WARN_ON_ONCE(1);
	return 0;
}
#endif

bool bpf_prog_array_compatible(struct bpf_array *array,
			       const struct bpf_prog *fp)
{
	if (fp->kprobe_override)
		return false;

	if (!array->aux->type) {
		


		array->aux->type  = fp->type;
		array->aux->jited = fp->jited;
		return true;
	}

	return array->aux->type  == fp->type &&
	       array->aux->jited == fp->jited;
}




























static void bpf_prog_select_func(struct bpf_prog *fp)
{
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	u32 stack_depth = max_t(u32, fp->aux->stack_depth, 1);
	dd("stack depth: %d", stack_depth);

	fp->bpf_func = interpreters[(round_up(stack_depth, 32) / 32) - 1];
#else
	fp->bpf_func = __bpf_prog_ret0_warn;
#endif
}









struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err)
{
	


	bool jit_needed = false;

	if (fp->bpf_func)
		goto finalize;





#if 1
	jit_needed = IS_ENABLED(CONFIG_BPF_JIT_ALWAYS_ON);
#endif

	bpf_prog_select_func(fp);

	





	if (!bpf_prog_is_dev_bound(fp->aux)) {
		*err = bpf_prog_alloc_jited_linfo(fp);
		if (*err)
			return fp;

		fp = bpf_int_jit_compile(fp);
		bpf_prog_jit_attempt_done(fp);
		if (!fp->jited && jit_needed) {
			*err = -ENOTSUPP;
			return fp;
		}
	} else {


#if 1
		*err = -ENOTSUPP;
#endif
		if (*err)
			return fp;
	}

finalize:
	bpf_prog_lock_ro(fp);










	return fp;
}
EXPORT_SYMBOL_GPL(bpf_prog_select_runtime);










































































































































































































































































void __bpf_free_used_maps(struct bpf_prog_aux *aux,
			  struct bpf_map **used_maps, u32 len)
{
	struct bpf_map *map;
	u32 i;

	for (i = 0; i < len; i++) {
		map = used_maps[i];




		bpf_map_put(map);
	}
}

static void bpf_free_used_maps(struct bpf_prog_aux *aux)
{
	__bpf_free_used_maps(aux, aux->used_maps, aux->used_map_cnt);
	kfree(aux->used_maps);
}

























static void bpf_prog_free_deferred(struct work_struct *work)
{
	struct bpf_prog_aux *aux;
	int i;

	aux = container_of(work, struct bpf_prog_aux, work);
	bpf_free_used_maps(aux);
	
	if (bpf_prog_is_dev_bound(aux))


#if 1
		;
#endif
#ifdef CONFIG_PERF_EVENTS
	if (aux->prog->has_callchain_buf)
		put_callchain_buffers();
#endif




	for (i = 0; i < aux->func_cnt; i++) {







		bpf_jit_free(aux->func[i]);
	}
	if (aux->func_cnt) {
		kfree(aux->func);
		bpf_prog_unlock_free(aux->prog);
	} else {
		bpf_jit_free(aux->prog);
	}
}

 
void bpf_prog_free(struct bpf_prog *fp)
{
	struct bpf_prog_aux *aux = fp->aux;

	if (aux->dst_prog)
		bpf_prog_put(aux->dst_prog);
	INIT_WORK(&aux->work, bpf_prog_free_deferred);
	schedule_work(&aux->work);
}
EXPORT_SYMBOL_GPL(bpf_prog_free);

 


void bpf_user_rnd_init_once(void)
{
	prandom_init_once(bpf_user_rnd_state);
}

BPF_CALL_0(bpf_user_rnd_u32)
{
	





	struct rnd_state *state;
	u32 res;

	state = get_cpu_ptr(bpf_user_rnd_state);
	res = prandom_u32_state(state);
	put_cpu_ptr(bpf_user_rnd_state);

	return res;
}

BPF_CALL_0(bpf_get_raw_cpu_id)
{
	return raw_smp_processor_id();
}

 
const struct bpf_func_proto bpf_map_lookup_elem_proto __weak;
const struct bpf_func_proto bpf_map_update_elem_proto __weak;
const struct bpf_func_proto bpf_map_delete_elem_proto __weak;
const struct bpf_func_proto bpf_map_push_elem_proto __weak;
const struct bpf_func_proto bpf_map_pop_elem_proto __weak;
const struct bpf_func_proto bpf_map_peek_elem_proto __weak;
const struct bpf_func_proto bpf_spin_lock_proto __weak;
const struct bpf_func_proto bpf_spin_unlock_proto __weak;
const struct bpf_func_proto bpf_jiffies64_proto __weak;

const struct bpf_func_proto bpf_get_prandom_u32_proto __weak;
const struct bpf_func_proto bpf_get_smp_processor_id_proto __weak;
const struct bpf_func_proto bpf_get_numa_node_id_proto __weak;
const struct bpf_func_proto bpf_ktime_get_ns_proto __weak;
const struct bpf_func_proto bpf_ktime_get_boot_ns_proto __weak;
const struct bpf_func_proto bpf_ktime_get_coarse_ns_proto __weak;

const struct bpf_func_proto bpf_find_vpid_proto __weak;
const struct bpf_func_proto bpf_get_current_pid_tgid_proto __weak;
const struct bpf_func_proto bpf_get_current_uid_gid_proto __weak;
const struct bpf_func_proto bpf_get_current_comm_proto __weak;
const struct bpf_func_proto bpf_get_current_cgroup_id_proto __weak;
const struct bpf_func_proto bpf_get_current_ancestor_cgroup_id_proto __weak;
const struct bpf_func_proto bpf_get_local_storage_proto __weak;
const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto __weak;
const struct bpf_func_proto bpf_snprintf_btf_proto __weak;
const struct bpf_func_proto bpf_seq_printf_btf_proto __weak;

const struct bpf_func_proto * __weak bpf_get_trace_printk_proto(void)
{
	return NULL;
}

u64 __weak
bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
		 void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy)
{
	return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(bpf_event_output);

















struct bpf_prog * __weak bpf_int_jit_compile(struct bpf_prog *prog)
{
	return prog;
}




void __weak bpf_jit_compile(struct bpf_prog *prog)
{
}

bool __weak bpf_helper_changes_pkt_data(void *func)
{
	return false;
}









bool __weak bpf_jit_needs_zext(void)
{
	return false;
}

bool __weak bpf_jit_supports_kfunc_call(void)
{
	return false;
}




int __weak skb_copy_bits(const struct sk_buff *skb, int offset, void *to,
			 int len)
{
	return -EFAULT;
}

int __weak bpf_arch_text_poke(void *ip, enum bpf_text_poke_type t,
			      void *addr1, void *addr2)
{
	return -ENOTSUPP;
}

DEFINE_STATIC_KEY_FALSE(bpf_stats_enabled_key);
EXPORT_SYMBOL(bpf_stats_enabled_key);

 
#define CREATE_TRACE_POINTS
#include <linux/bpf_trace.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(xdp_exception);
EXPORT_TRACEPOINT_SYMBOL_GPL(xdp_bulk_tx);

int bpf_pcpu_bpf_user_rnd_state_init0(void) { bpf_user_rnd_state = alloc_percpu(struct rnd_state); if (unlikely(bpf_user_rnd_state == NULL)) { return -ENOMEM; } return 0; }
void bpf_pcpu_bpf_user_rnd_state_exit0(void) { free_percpu(bpf_user_rnd_state); }