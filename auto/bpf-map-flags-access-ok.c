#include <linux/bpf.h>

bool foo(u32 access_flags)
{
	return bpf_map_flags_access_ok(access_flags);
}
