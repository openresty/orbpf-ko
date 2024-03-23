#include <linux/bpf.h>
#include <linux/filter.h>

bool foo(int off, int size, enum bpf_access_type type,
	struct bpf_insn_access_aux *info)
{
	return bpf_sock_common_is_valid_access(off, size, type, info);
}
