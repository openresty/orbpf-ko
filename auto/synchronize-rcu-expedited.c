#include <linux/rcupdate.h>

void foo(void) {
	synchronize_rcu_expedited();
}
