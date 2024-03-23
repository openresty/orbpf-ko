#include <linux/mm.h>

struct vm_area_struct *foo(struct mm_struct *mm) {
	return mm->mmap;
}
