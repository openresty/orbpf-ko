#include <linux/mm.h>

void foo(struct vm_area_struct *vma) {
	vm_flags_clear(vma, VM_MAYEXEC);
}
