#include <linux/bpf.h>
#include <linux/btf.h>

const struct btf_var_secinfo *foo(const struct btf_type *t)
{
	return btf_type_var_secinfo(t);
}
