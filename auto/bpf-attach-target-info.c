#include <linux/bpf.h>

long foo(struct bpf_attach_target_info *p)
{
	return p->tgt_addr;
}
