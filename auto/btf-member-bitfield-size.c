#include <linux/bpf.h>
#include <linux/btf.h>

int foo(const struct btf_type *t, const struct btf_member *member)
{
	return btf_member_bit_offset(t, member);
}
