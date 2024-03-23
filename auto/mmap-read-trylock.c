#include <linux/mm.h>

void foo(struct mm_struct *mm) {
	if (mmap_read_trylock(mm))
		mmap_read_unlock(mm);
}
