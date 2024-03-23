#include <linux/bpf.h>

int foo(struct bpf_map *m)
{
	return m->spin_lock_off;
}
