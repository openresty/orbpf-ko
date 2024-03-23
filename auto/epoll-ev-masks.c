#include <linux/poll.h>

unsigned foo(void) {
	return EPOLLIN | EPOLLERR | EPOLLRDNORM;
}
