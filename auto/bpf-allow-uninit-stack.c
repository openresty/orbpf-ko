#include <linux/bpf.h>

bool foo(void)
{
	return bpf_allow_uninit_stack();
}
