#include <linux/bpf.h>

bool foo(struct bpf_map *m)
{
	return m->frozen;
}
