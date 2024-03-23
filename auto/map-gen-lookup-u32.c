#include <linux/bpf.h>

typedef u32 (*my_map_gen_lookup_t)(struct bpf_map *map, struct bpf_insn *insn_buf);

my_map_gen_lookup_t foo(struct bpf_map_ops *p)
{
	return p->map_gen_lookup;
}
