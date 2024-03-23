#include <linux/atomic.h>
#include <linux/bpf.h>

atomic64_t *foo(struct bpf_map *map)
{
	return &map->refcnt;
}

