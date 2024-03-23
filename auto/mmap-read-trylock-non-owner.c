#include <linux/mm.h>

bool foo(struct mm_struct *mm) {
	return mmap_read_trylock_non_owner(mm);
}
