#include <linux/bpf.h>

bool foo(int off, int size, enum bpf_access_type type,
		struct bpf_insn_access_aux *info)
{
	return bpf_xdp_sock_is_valid_access(off, size, type, info);
}
