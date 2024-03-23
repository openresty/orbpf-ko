#include <linux/bpf.h>

u64 foo(struct bpf_map *m)
{
	return m->writecnt;
}
