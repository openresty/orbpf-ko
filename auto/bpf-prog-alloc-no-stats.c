#include <linux/bpf.h>

struct bpf_prog *foo(unsigned int size, gfp_t gfp_extra_flags)
{
	return bpf_prog_alloc_no_stats(size, gfp_extra_flags);
}
