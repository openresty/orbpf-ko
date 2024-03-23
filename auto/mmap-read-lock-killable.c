#include <linux/mm.h>

int foo(struct mm_struct *mm) {
	return mmap_read_lock_killable(mm);
}
