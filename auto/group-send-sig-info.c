#include <linux/signal.h>

int foo(int sig, struct kernel_siginfo *info,
                   struct task_struct *p, enum pid_type type);
{
	return group_send_sig_info(sig, info, p, type);
}
