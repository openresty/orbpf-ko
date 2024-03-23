#include <linux/filter.h>

int foo(u32 off, u32 size, u32 size_default)
{
	return bpf_ctx_narrow_access_offset(off, size, size_default);
}
