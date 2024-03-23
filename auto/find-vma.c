#include <linux/mm.h>

struct vm_area_struct *foo(struct mm_struct *mm) {
	return find_vma(mm, 0);
}
