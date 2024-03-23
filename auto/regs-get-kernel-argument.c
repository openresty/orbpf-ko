#include <asm/ptrace.h>

unsigned long foo(struct pt_regs *regs, unsigned int n)
{
	return regs_get_kernel_argument(regs, n);
}
