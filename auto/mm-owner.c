#include <linux/mm.h>

struct task_struct *foo(struct mm_struct *mm) {
	return mm->owner;
}
