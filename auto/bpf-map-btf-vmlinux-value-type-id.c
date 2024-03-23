#include <linux/bpf.h>

u32 foo(struct bpf_map *m)
{
	return m->btf_vmlinux_value_type_id;
}
