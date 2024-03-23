#include <linux/bpf.h>
#include <linux/atomic.h>

atomic_t *foo(struct bpf_map *m)
{
	return &m->usercnt;
}
