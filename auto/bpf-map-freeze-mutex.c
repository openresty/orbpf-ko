#include <linux/bpf.h>

void foo(struct bpf_map *m)
{
	mutex_lock(&m->freeze_mutex);
}
