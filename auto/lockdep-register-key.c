#include <linux/lockdep.h>

void foo(struct lock_class_key *key) {
	lockdep_register_key(key);
	lockdep_unregister_key(key);
}
