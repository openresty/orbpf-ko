#include <linux/mm.h>

void foo(struct mm_struct *mm) {
	mmap_read_unlock_non_owner(mm);
}
