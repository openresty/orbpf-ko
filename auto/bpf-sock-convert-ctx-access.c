#include <linux/bpf.h>
#include <linux/filter.h>

u32 foo(enum bpf_access_type type, const struct bpf_insn *si,
	struct bpf_insn *insn_buf, struct bpf_prog *prog,
	u32 *target_size)
{
	return bpf_tcp_sock_convert_ctx_access(type, si, insn_buf, prog, target_size);
}


