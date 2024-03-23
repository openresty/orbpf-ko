/* Copyright (C) by OpenResty Inc. All rights reserved. */



#ifndef __MMAP_UNLOCK_WORK_H__
#define __MMAP_UNLOCK_WORK_H__
#include <linux/irq_work.h>

 
struct mmap_unlock_irq_work {
	struct irq_work irq_work;
	struct mm_struct *mm;
};

 

extern struct mmap_unlock_irq_work __percpu *mmap_unlock_work;

#ifdef ORBPF_CONF_MMAP_READ_TRYLOCK








static inline bool bpf_mmap_unlock_get_irq_work(struct mmap_unlock_irq_work **work_ptr)
{
	struct mmap_unlock_irq_work *work = NULL;
	bool irq_work_busy = false;

	if (irqs_disabled()) {
		if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
			work = this_cpu_ptr(mmap_unlock_work);
			if (irq_work_is_busy(&work->irq_work)) {
				 
				irq_work_busy = true;
			}
		} else {
			



			irq_work_busy = true;
		}
	}

	*work_ptr = work;
	return irq_work_busy;
}

static inline void bpf_mmap_unlock_mm(struct mmap_unlock_irq_work *work, struct mm_struct *mm)
{
	if (!work) {



		mmap_read_unlock(mm);
	} else {
		work->mm = mm;

		








		irq_work_queue(&work->irq_work);
	}
}

static inline void orbpf_lockdep_release_mmap_lock(struct mm_struct *mm)
{
	



#ifdef ORBPF_CONF_RWSEM_RELEASE_3_ARGS
	rwsem_release(&mm->mmap_sem.dep_map, NULL, _RET_IP_);
#else
	rwsem_release(&mm->mmap_sem.dep_map, _RET_IP_);
#endif
}

#endif   

#endif  