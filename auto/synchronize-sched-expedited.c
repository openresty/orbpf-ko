#include <linux/rcupdate.h>

void foo(void) {
	synchronize_sched_expedited();
}
