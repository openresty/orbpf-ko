#include <linux/mm.h>

void *foo(struct mm_struct *mm) {
	return &mm->mmap_lock;
}
