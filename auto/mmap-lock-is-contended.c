#include <linux/mm.h>

int foo(struct mm_struct *mm) {
	return mmap_lock_is_contended(mm);
}
