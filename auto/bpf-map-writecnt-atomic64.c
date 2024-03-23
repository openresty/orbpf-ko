#include <linux/bpf.h>

u64 foo(struct bpf_map *map)
{
	return atomic64_read(&map->writecnt);
}
