#include <linux/rwsem.h>

void foo(struct rw_semaphore *sem)
{
	rwsem_release(sem, NULL, _RET_IP_);
}
