#include <linux/bpf.h>

int foo(void)
{
	return BPF_F_MMAPABLE;
}
