/* Copyright (C) by OpenResty Inc. All rights reserved. */
 

#include <linux/orbpf_conf.h>
#include <linux/anon_inodes.h>
#include <linux/binfmts.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/perf_event.h>

 
#define ORBPF_GFP_NOSLEEP (GFP_KERNEL & ~__GFP_DIRECT_RECLAIM)

#define ORBPF_KRETPROBE_MAXACTIVE  max_t(int, 15, 6 * NR_CPUS)

struct orbpf_kprobe_priv {
	struct bpf_prog *prog;
	union {
		struct kprobe kp;
		struct kretprobe krp;
	};
	pid_t tgid;
	pid_t pgid;
	pid_t ppid;
	bool  is_ret;
};

struct orbpf_uprobe_priv {
	struct bpf_prog *prog;
	struct uprobe_consumer consumer;
	struct inode *inode;
	unsigned long off;
	pid_t tgid;
	pid_t pgid;
	pid_t ppid;
};

struct orbpf_perf_priv {
	struct bpf_prog *prog;
	struct perf_event *task_evt;
	struct perf_event __percpu **syswide_evt;
	pid_t tgid;
	pid_t pgid;
	pid_t ppid;
};

struct orbpf_tf_priv {
	struct bpf_prog *prog;
	struct inode *inode;
	struct list_head tfw_list;
	struct wait_queue_head exit_waitq;
	struct completion init_done;
	struct rw_semaphore init_rwsem;
	struct task_struct *task_ref;
	struct pid *pgid_ref;
	struct pid *ppid_ref;
	spinlock_t tfw_list_lock;
	atomic_t init_count;
	atomic_t refs;
	pid_t tgid;
	pid_t pgid;
	pid_t ppid;
	bool pid_trace_exec;
};

struct orbpf_tf_work {
	struct callback_head twork;
	struct orbpf_tf_priv *p;
	struct task_struct *task;
	struct list_head node;
};

void __printk_safe_enter(void);
void __printk_safe_exit(void);

static struct tracepoint *sched_exec_tp;
static struct tracepoint *sched_fork_tp;

struct bpf_prog * __percpu *pcpu_bpf_programs;



static inline bool
orbpf_is_target(struct task_struct *task, pid_t tgid,
	pid_t pgid, pid_t ppid)
{




	if (tgid == 0) {
		return false;
	}

	 
	return (tgid == -1 || tgid == task->tgid) &&
	    (pgid <= 0 || pgid == task_pgrp_nr(task)) &&
	    (ppid <= 0 || ppid == task_ppid_nr(task));
}

static int orbpf_run_prog(struct bpf_prog *prog, void *ctx)
{
	unsigned long flags;
	int ret = 0;

	











	local_irq_save(flags);
	if (likely(__this_cpu_inc_return(*bpf_prog_active) == 1)) {
		__printk_safe_enter();
		preempt_disable();

		this_cpu_write(*pcpu_bpf_programs, prog);

		local_irq_restore(flags);
		rcu_read_lock();
		ret = BPF_PROG_RUN(prog, ctx);
		rcu_read_unlock();
		local_irq_save(flags);

		this_cpu_write(*pcpu_bpf_programs, NULL);

		preempt_enable();
		__printk_safe_exit();
	}
	__this_cpu_dec(*bpf_prog_active);
	local_irq_restore(flags);

	return ret;
}

static int orbpf_kprobe_handler(struct kprobe *kp, struct pt_regs *regs)
{
	struct orbpf_kprobe_priv *p = container_of(kp, typeof(*p), kp);

	if (orbpf_is_target(current, p->tgid, p->pgid, p->ppid))
		orbpf_run_prog(p->prog, regs);

	

	return 0;
}

static int orbpf_kretprobe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *krp =
#ifdef ORBPF_CONF_KRETPROBE_INSTANCE_RP
		ri->rp;
#elif defined(ORBPF_CONF_GET_KRETPROBE)
		get_kretprobe(ri);
#else
#error "No implementation for get_kretprobe()"
#endif
	struct orbpf_kprobe_priv *p = container_of(krp, typeof(*p), krp);

	if (orbpf_is_target(current, p->tgid, p->pgid, p->ppid))
		orbpf_run_prog(p->prog, regs);

	return 0;
}

static inline void
orbpf_handle_kprobe_unreg_failure(struct orbpf_kprobe_priv *p, unsigned long ip)
{
	struct bpf_prog *prog = p->prog;

#define ORBPF_ERR_MSG  "BUG: failed to unregister kprobe at %s ip=%lx"
	if (likely(prog != NULL && prog->prog_label_len > 0)) {
		pr_err(ORBPF_ERR_MSG " prog: %s\n", p->kp.symbol_name, ip,
		       prog->prog_label);
	} else {
		pr_err(ORBPF_ERR_MSG "\n", p->kp.symbol_name, ip);
	}
#undef ORBPF_ERR_MSG
}

static int orbpf_kprobe_release(struct inode *inode, struct file *filp)
{
	struct orbpf_kprobe_priv *p;

	 
	p = filp->private_data;
	if (unlikely(!p))
		return 0;

	if (p->is_ret) {
		unsigned long ip = (unsigned long)p->krp.kp.addr;
		unregister_kretprobe(&p->krp);
		if (unlikely(ip != 0 && p->krp.kp.addr == NULL)) {
			orbpf_handle_kprobe_unreg_failure(p, ip);
			

			return 0;
		}
		kfree_const(p->krp.kp.symbol_name);

	} else {
		unsigned long ip = (unsigned long)p->kp.addr;
		unregister_kprobe(&p->kp);
		if (unlikely(ip != 0 && p->kp.addr == NULL)) {
			orbpf_handle_kprobe_unreg_failure(p, ip);
			 
			return 0;
		}
		kfree_const(p->kp.symbol_name);
	}
	bpf_prog_put(p->prog);
	kfree(p);
	return 0;
}

static const struct file_operations orbpf_kprobe_fops = {
	.owner = THIS_MODULE,
	.release = orbpf_kprobe_release
};

static int orbpf_attach_kprobe(struct orbpf_kprobe *k)
{
	struct orbpf_kprobe_priv *p;
	struct bpf_prog *prog;
	struct file *filp;
	char *func;
	int fd, ret;

	prog = bpf_prog_get(k->prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->type != BPF_PROG_TYPE_KPROBE) {
		ret = -EINVAL;
		goto put_prog;
	}

	func = kmalloc(KSYM_NAME_LEN, GFP_KERNEL);
	if (!func) {
		ret = -ENOMEM;
		goto put_prog;
	}

	ret = strncpy_from_user(func, u64_to_user_ptr(k->func), KSYM_NAME_LEN);
	if (ret == KSYM_NAME_LEN)
		ret = -E2BIG;
	if (ret < 0)
		goto free_func;
	func[ret] = '\0';

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto free_func;
	}

	ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		goto free_p;

	fd = ret;
	filp = anon_inode_getfile("orbpf-kprobe", &orbpf_kprobe_fops, NULL,
				  O_CLOEXEC);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		goto put_fd;
	}

	p->prog = prog;

	if (k->pid > 0) {
		rcu_read_lock();
		p->tgid = pid_nr(find_vpid(k->pid));
		rcu_read_unlock();

		if (unlikely(p->tgid == 0)) {
			pr_err("cannot find user-supplied pid %d\n",
			       k->pid);
			ret = -ESRCH;
			goto put_filp;
		}

	} else if (k->pid == -1) {   
		p->tgid = -1;

	} else if (k->pid < 0) {
		rcu_read_lock();
		p->pgid = pid_nr(find_vpid(-k->pid));
		rcu_read_unlock();

		if (unlikely(p->pgid == 0)) {
			pr_err("cannot find user-supplied pgid %d\n",
			       -k->pid);
			ret = -ESRCH;
			goto put_filp;
		}

	} else {
		 
	}

	if (k->ppid > 0) {
		rcu_read_lock();
		p->ppid = pid_nr(find_vpid(k->ppid));
		rcu_read_unlock();

		if (unlikely(p->ppid == 0)) {
			pr_err("cannot find user-supplied ppid %d\n",
			       k->ppid);
			ret = -ESRCH;
			goto put_filp;
		}
	}

	if (k->retprobe) {
		p->is_ret = true;
		p->krp.handler = orbpf_kretprobe_handler;
		p->krp.maxactive = ORBPF_KRETPROBE_MAXACTIVE;
		p->krp.kp.symbol_name = func;
		ret = register_kretprobe(&p->krp);

	} else {
		p->kp.symbol_name = func;
		p->kp.pre_handler = orbpf_kprobe_handler;




		ret = register_kprobe(&p->kp);
	}

	if (ret)
		goto put_filp;

	 
	filp->private_data = p;
	fd_install(fd, filp);
	return fd;

put_filp:
	fput(filp);
put_fd:
	put_unused_fd(fd);
free_p:
	kfree(p);
free_func:
	kfree(func);
put_prog:
	bpf_prog_put(prog);
	return ret;
}

static int
orbpf_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs)
{
	struct orbpf_uprobe_priv *p = container_of(uc, typeof(*p), consumer);

	



	if (unlikely(!orbpf_is_target(current, p->tgid, p->pgid, p->ppid))) {
		return UPROBE_HANDLER_REMOVE;
	}

	orbpf_run_prog(p->prog, regs);
	return 0;
}












static int orbpf_uprobe_release(struct inode *inode, struct file *filp)
{
	struct orbpf_uprobe_priv *p;

	 
	p = filp->private_data;
	if (unlikely(!p))
		return 0;

	uprobe_unregister(p->inode, p->off, &p->consumer);
	iput(p->inode);
	bpf_prog_put(p->prog);
	kfree(p);
	return 0;
}

static const struct file_operations orbpf_uprobe_fops = {
	.owner = THIS_MODULE,
	.release = orbpf_uprobe_release
};

static struct inode *orbpf_get_user_inode(void __user *user_path)
{
	struct inode *inode;
	struct path path;
	char *filename;
	int ret;

	filename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!filename)
		return ERR_PTR(-ENOMEM);

	ret = strncpy_from_user(filename, user_path, PATH_MAX);
	if (ret == PATH_MAX)
		ret = -E2BIG;
	if (ret < 0) {
		kfree(filename);
		return ERR_PTR(ret);
	}
	filename[ret] = '\0';

	ret = kern_path(filename, LOOKUP_FOLLOW, &path);
	kfree(filename);
	if (ret)
		return ERR_PTR(ret);

	if (d_is_reg(path.dentry)) {
		inode = d_real_inode(path.dentry);
		ihold(inode);
	} else {
		inode = ERR_PTR(-EINVAL);
	}
	path_put(&path);
	return inode;
}

#if defined(ORBPF_CONF_UPROBE_FILTER_CTX) && defined(ORBPF_CONF_MM_OWNER)
static bool
orbpf_uprobe_filter(struct uprobe_consumer *self, enum uprobe_filter_ctx ctx,
	struct mm_struct *mm)
{
	struct orbpf_uprobe_priv *p = container_of(self, typeof(*p), consumer);
	struct task_struct *task = mm->owner;
	if (unlikely(task == NULL))
		return false;
	return orbpf_is_target(task, p->tgid, p->pgid, p->ppid);
}
#endif

static int orbpf_attach_uprobe(struct orbpf_uprobe *u)
{
	struct orbpf_uprobe_priv *p;
	struct bpf_prog *prog;
	struct inode *inode;
	struct file *filp;
	int fd, ret;

	prog = bpf_prog_get(u->prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->type != BPF_PROG_TYPE_KPROBE) {
		ret = -EINVAL;
		goto put_prog;
	}

	inode = orbpf_get_user_inode(u64_to_user_ptr(u->filename));
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto put_prog;
	}

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto put_inode;
	}

	ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		goto free_p;

	fd = ret;
	filp = anon_inode_getfile("orbpf-uprobe", &orbpf_uprobe_fops, NULL,
				  O_CLOEXEC);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		goto put_fd;
	}

	if (u->retprobe) {
		return -ENOTSUPP;
	}

	p->prog = prog;

	if (u->pid > 0) {
		rcu_read_lock();
		p->tgid = pid_nr(find_vpid(u->pid));
		rcu_read_unlock();

		if (unlikely(p->tgid == 0)) {
			pr_err("cannot find user-supplied pid %d\n",
			       u->pid);
			ret = -ESRCH;
			goto put_filp;
		}

	} else if (u->pid == -1) {   
		p->tgid = -1;

	} else if (u->pid < 0) {
		rcu_read_lock();
		p->pgid = pid_nr(find_vpid(-u->pid));
		rcu_read_unlock();

		if (unlikely(p->pgid == 0)) {
			pr_err("cannot find user-supplied pgid %d\n",
			       -u->pid);
			ret = -ESRCH;
			goto put_filp;
		}

	} else {
		 
	}

	if (u->ppid > 0) {
		rcu_read_lock();
		p->ppid = pid_nr(find_vpid(u->ppid));
		rcu_read_unlock();

		if (unlikely(p->ppid == 0)) {
			pr_err("cannot find user-supplied ppid %d\n",
			       u->ppid);
			ret = -ESRCH;
			goto put_filp;
		}
	}

#if defined(ORBPF_CONF_UPROBE_FILTER_CTX) && defined(ORBPF_CONF_MM_OWNER)
	p->consumer.filter = orbpf_uprobe_filter;
#endif
	p->consumer.handler = orbpf_uprobe_handler;

	ret = uprobe_register(inode, u->offset, &p->consumer);
	if (ret)
		goto put_filp;

	 
	p->inode = inode;
	p->off = u->offset;

	 
	filp->private_data = p;
	fd_install(fd, filp);
	return fd;

put_filp:
	fput(filp);
put_fd:
	put_unused_fd(fd);
free_p:
	kfree(p);
put_inode:
	iput(inode);
put_prog:
	bpf_prog_put(prog);
	return ret;
}

static void orbpf_perf_handler(struct perf_event *event,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
	struct orbpf_perf_priv *p = event->overflow_handler_context;
	struct bpf_perf_event_data_kern perf_event_data = {
#ifdef CONFIG_X86_64
		.regs = regs,
#elif CONFIG_ARM64
		.regs = &regs->user_regs,
#endif
		.data = data,
		.event = event
	};
	struct bpf_prog *prog;

	if (!orbpf_is_target(current, p->tgid, p->pgid, p->ppid))
		return;

	prog = READ_ONCE(p->prog);
	if (unlikely(!prog))
		return;

	switch (prog->type) {
	case BPF_PROG_TYPE_TRACEPOINT:
		orbpf_run_prog(prog, data->raw->frag.data);
		break;
	case BPF_PROG_TYPE_PERF_EVENT:
		orbpf_run_prog(prog, &perf_event_data);
		break;
	default:
		break;
	}
}

static int orbpf_perf_release(struct inode *inode, struct file *filp)
{
	struct orbpf_perf_priv *p;
	struct perf_event *evt;
	int cpu;

	 
	p = filp->private_data;
	if (unlikely(!p))
		return 0;

	if (p->task_evt) {
		perf_event_release_kernel(p->task_evt);
	} else {
		for_each_possible_cpu(cpu) {
			evt = *per_cpu_ptr(p->syswide_evt, cpu);
			perf_event_release_kernel(evt);
			cond_resched();
		}
		free_percpu(p->syswide_evt);
	}
	bpf_prog_put(p->prog);
	kfree(p);
	return 0;
}

static const struct file_operations orbpf_perf_fops = {
	.owner = THIS_MODULE,
	.release = orbpf_perf_release
};

static struct task_struct *orbpf_get_task_by_pid(pid_t pid)
{
	struct task_struct *task;

	if (!pid) {
		get_task_struct(current);
		return current;
	}

	 
	rcu_read_lock();
	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	return task;
}

static int orbpf_attach_perf(struct orbpf_perf *e)
{
	struct perf_event_attr attr;
	struct orbpf_perf_priv *p;
	struct task_struct *task = NULL;
	struct perf_event *evt;
	struct bpf_prog *prog;
	struct file *filp;
	int cpu, fd, ret;

	prog = bpf_prog_get(e->prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->type != BPF_PROG_TYPE_PERF_EVENT &&
	    prog->type != BPF_PROG_TYPE_TRACEPOINT) {
		ret = -EINVAL;
		goto put_prog;
	}

	if (copy_from_user(&attr, u64_to_user_ptr(e->attr), sizeof(attr))) {
		ret = -EFAULT;
		goto put_prog;
	}

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto put_prog;
	}

	ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		goto free_p;

	fd = ret;
	filp = anon_inode_getfile("orbpf-perf", &orbpf_perf_fops, NULL,
				  O_CLOEXEC);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		goto put_fd;
	}

	if (e->pid > 0) {
		task = orbpf_get_task_by_pid(e->pid);
		if (unlikely(task == NULL)) {



			ret = -ESRCH;
			goto put_filp;
		}

		p->tgid = task->tgid;
		if (unlikely(p->tgid == 0)) {
			pr_err("cannot find user-supplied pid %d\n",
			       e->pid);
			ret = -ESRCH;
			goto put_filp;
		}

	} else if (e->pid == -1) {   
		p->tgid = -1;

	} else if (e->pid < 0) {
		rcu_read_lock();
		p->pgid = pid_nr(find_vpid(-e->pid));
		rcu_read_unlock();

		if (unlikely(p->pgid == 0)) {
			pr_err("cannot find user-supplied pgid %d\n",
			       -e->pid);
			ret = -ESRCH;
			goto put_filp;
		}

	} else {
		 
	}

	if (e->ppid > 0) {
		rcu_read_lock();
		p->ppid = pid_nr(find_vpid(e->ppid));
		rcu_read_unlock();

		if (unlikely(p->ppid == 0)) {
			pr_err("cannot find user-supplied ppid %d\n",
			       e->ppid);
			ret = -ESRCH;
			goto put_filp;
		}
	}





	if (p->tgid <= 0) {
		p->syswide_evt = alloc_percpu(typeof(*p->syswide_evt));
		if (!p->syswide_evt) {
			ret = -ENOMEM;
			goto put_filp;
		}

		 
		for_each_possible_cpu(cpu) {
			evt = perf_event_create_kernel_counter(&attr, cpu, NULL,
							orbpf_perf_handler, p);
			if (IS_ERR(evt)) {
				ret = PTR_ERR(evt);
				goto release_events;
			}
			*per_cpu_ptr(p->syswide_evt, cpu) = evt;
			cond_resched();
		}
	} else {
		 
		 
		p->task_evt = perf_event_create_kernel_counter(&attr, -1, task,
							orbpf_perf_handler, p);
		



		put_task_struct(task);
		task = NULL;
		if (IS_ERR(p->task_evt)) {
			ret = PTR_ERR(p->task_evt);



			goto put_filp;
		}
	}

	 
	WRITE_ONCE(p->prog, prog);

	 
	filp->private_data = p;
	fd_install(fd, filp);
	return fd;

release_events:
	while (cpu--) {
		evt = *per_cpu_ptr(p->syswide_evt, cpu);
		perf_event_release_kernel(evt);
	}
	free_percpu(p->syswide_evt);

put_filp:
	if (task)
		put_task_struct(task);
	fput(filp);

put_fd:
	put_unused_fd(fd);
free_p:
	kfree(p);
put_prog:
	bpf_prog_put(prog);
	return ret;
}






static bool orbpf_tf_init_lock(struct orbpf_tf_priv *p)
{
	unsigned int cnt;

	cnt = atomic_read(&p->init_count);
	do {
		if (likely(cnt & BIT(31)))
			return false;
	} while (!atomic_try_cmpxchg(&p->init_count, &cnt, cnt + 1));

	return true;
}





static void orbpf_tf_init_unlock(struct orbpf_tf_priv *p)
{
	unsigned int cnt;

	cnt = atomic_read(&p->init_count);
	do {
		if (cnt == (BIT(31) | 1)) {
			complete(&p->init_done);
			return;
		}
	} while (!atomic_try_cmpxchg(&p->init_count, &cnt, cnt - 1));
}





static bool orbpf_tf_init_done(struct orbpf_tf_priv *p)
{
	return atomic_fetch_or(BIT(31), &p->init_count);
}

static void orbpf_tfw_del(struct orbpf_tf_work *tfw)
{
	struct orbpf_tf_priv *p = tfw->p;

	spin_lock(&p->tfw_list_lock);
	list_del(&tfw->node);
	spin_unlock(&p->tfw_list_lock);
	kfree(tfw);
}

static void orbpf_tf_worker(struct callback_head *twork)
{
	struct orbpf_tf_work *tfw = container_of(twork, typeof(*tfw), twork);
	struct orbpf_tf_priv *p = tfw->p;
	struct task_struct *task = current;

	 
	orbpf_tfw_del(tfw);

	




	if (likely(!(current->flags & PF_EXITING) &&
		   orbpf_is_target(task, p->tgid, p->pgid, p->ppid) &&
		   file_inode(task->mm->exe_file) == p->inode))
    {
		orbpf_run_prog(p->prog, task_pt_regs(current));
	}

	if (atomic_dec_and_test(&p->refs))
		wake_up(&p->exit_waitq);
}

static void orbpf_tfw_init(struct orbpf_tf_priv *p, struct orbpf_tf_work *tfw)
{
	tfw->p = p;
	atomic_inc(&p->refs);
	init_task_work(&tfw->twork, orbpf_tf_worker);
	spin_lock(&p->tfw_list_lock);
	list_add(&tfw->node, &p->tfw_list);
	spin_unlock(&p->tfw_list_lock);
}





static bool orbpf_tfw_found(struct orbpf_tf_priv *p, struct task_struct *task)
{
	struct callback_head **pprev = &task->task_works;
	struct callback_head *work;
	unsigned long flags;

	if (!task->task_works)
		return false;

	



	raw_spin_lock_irqsave(&task->pi_lock, flags);
	while ((work = READ_ONCE(*pprev))) {
		if (work->func == orbpf_tf_worker &&
		    container_of(work, struct orbpf_tf_work, twork)->p == p) {
			raw_spin_unlock_irqrestore(&task->pi_lock, flags);
			return true;
		}
		pprev = &work->next;
	}
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	return false;
}








static bool orbpf_tfw_cancel(struct orbpf_tf_work *tfw)
{
	struct task_struct *task = tfw->task;
	struct callback_head **pprev = &task->task_works;
	struct callback_head *work;
	unsigned long flags;

	if (!task->task_works)
		return false;

	



	raw_spin_lock_irqsave(&task->pi_lock, flags);
	while ((work = READ_ONCE(*pprev))) {
		if (container_of(work, typeof(*tfw), twork) != tfw) {
			pprev = &work->next;
		} else if (cmpxchg(pprev, work, work->next) == work) {
			raw_spin_unlock_irqrestore(&task->pi_lock, flags);
			return true;
		}
	}
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	return false;
}

 
static bool orbpf_tfw_cancel_all(struct orbpf_tf_priv *p)
{
	struct orbpf_tf_work *tfw;
	int num_cancelled = 0;

	while (1) {
		spin_lock(&p->tfw_list_lock);
		tfw = list_first_entry_or_null(&p->tfw_list, typeof(*tfw), node);
		if (!tfw) {
			spin_unlock(&p->tfw_list_lock);
			break;
		}

		





		if (orbpf_tfw_cancel(tfw)) {
			list_del(&tfw->node);
			kfree(tfw);
			num_cancelled++;
		} else {
			list_del_init(&tfw->node);
		}
		spin_unlock(&p->tfw_list_lock);
		cond_resched();
	}

	return atomic_sub_return(num_cancelled, &p->refs);
}

static void orbpf_tf_tracer(struct orbpf_tf_priv *p, struct task_struct *task)
{
	struct orbpf_tf_work *tfw = NULL;

	if (unlikely(orbpf_tf_init_lock(p))) {
		

































#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
		rcu_read_unlock_sched_notrace();
#else
		preempt_enable_notrace();
#endif
		




		if (!down_read_killable(&p->init_rwsem)) {
			 
			if (!orbpf_tfw_found(p, task))
				tfw = kmalloc(sizeof(*tfw), GFP_KERNEL);
			up_read(&p->init_rwsem);
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
		rcu_read_lock_sched_notrace();
#else
		preempt_disable_notrace();
#endif
		orbpf_tf_init_unlock(p);
	} else {
		tfw = kmalloc(sizeof(*tfw), ORBPF_GFP_NOSLEEP);
	}

	if (tfw) {
		



		tfw->task = task;
		orbpf_tfw_init(p, tfw);
		orbpf_task_work_add(task, &tfw->twork);
	}
}

static void orbpf_exec_cb(void *data, struct task_struct *task, pid_t old_pid,
			  struct linux_binprm *bprm)
{
	struct orbpf_tf_priv *p = data;

	 
	if (unlikely(!atomic_read_acquire(&p->refs)))
		return;

	 
	if (task->pid == task->tgid &&
	    orbpf_is_target(task, p->tgid, p->pgid, p->ppid) &&
	    file_inode(bprm->file) == p->inode)
		orbpf_tf_tracer(p, task);
}

static void orbpf_fork_cb(void *data, struct task_struct *parent,
			  struct task_struct *child)
{
	struct orbpf_tf_priv *p = data;

	 
	if (unlikely(!atomic_read_acquire(&p->refs)))
		return;

	



	if (!(child->flags & PF_KTHREAD) &&
	    child->pid == child->tgid &&
	    orbpf_is_target(child, p->tgid, p->pgid, p->ppid) &&
	    child->mm &&
	    child->mm->exe_file &&
	    file_inode(child->mm->exe_file) == p->inode)
		orbpf_tf_tracer(p, child);
}

 
static struct orbpf_tf_work *orbpf_tf_do_scan(struct orbpf_tf_work *tfw,
					      struct orbpf_tf_priv *p,
					      struct task_struct *task)
{
	struct file *exe_file;
	struct mm_struct *mm;
	struct inode *inode;

	if (task->flags & (PF_KTHREAD | PF_EXITING)) {
		return tfw;
	}

	






	mm = READ_ONCE(task->mm);
	if (!mm || get_kernel_nofault(exe_file, &mm->exe_file) ||
	    get_kernel_nofault(inode, &exe_file->f_inode) || inode != p->inode) {
		return tfw;
	}

	if (!tfw) {
		tfw = kmalloc(sizeof(*tfw), ORBPF_GFP_NOSLEEP);
		if (!tfw) {
			return NULL;
		}

		orbpf_tfw_init(p, tfw);
	}

	




	tfw->task = task;
	if (likely(orbpf_task_work_add(task, &tfw->twork) == 0)) {
		return NULL;
	}

	return tfw;
}

static void orbpf_tf_scan(struct orbpf_tf_priv *p, struct task_struct *task_ref)
{
	struct orbpf_tf_work *tfw = NULL;
	struct task_struct *task;

	if (task_ref) {
		 
		tfw = orbpf_tf_do_scan(tfw, p, task_ref);

	} else if (p->pgid_ref) {
		 
		do_each_pid_task(p->pgid_ref, PIDTYPE_PGID, task) {
			tfw = orbpf_tf_do_scan(tfw, p, task);
		} while_each_pid_task(p->pgid_ref, PIDTYPE_PGID, task);

	} else if (p->ppid_ref) {
		 
		struct list_head *list;
		struct task_struct *child;

		task = pid_task(p->ppid_ref, PIDTYPE_PID);
		if (unlikely(task != NULL)) {
			list_for_each(list, &task->children) {
				child = list_entry(list, struct task_struct, sibling);
				tfw = orbpf_tf_do_scan(tfw, p, child);
			}
		}

	} else {
		 
		for_each_process(task)
			tfw = orbpf_tf_do_scan(tfw, p, task);
	}

	 
	if (unlikely(tfw)) {
		orbpf_tfw_del(tfw);
		atomic_dec(&p->refs);
	}
}

static void orbpf_tp_unregister_sync(void)
{
	





	orbpf_synchronize_sched();
}

static int orbpf_tf_release(struct inode *inode, struct file *filp)
{
	struct orbpf_tf_priv *p;

	 
	p = filp->private_data;
	if (unlikely(!p))
		return 0;

	 
	if (!p->task_ref || p->pid_trace_exec) {
		tracepoint_probe_unregister(sched_exec_tp, orbpf_exec_cb, p);
		if (!p->pid_trace_exec)
			tracepoint_probe_unregister(sched_fork_tp,
						    orbpf_fork_cb, p);
		orbpf_tp_unregister_sync();
	}

	 
	if (atomic_dec_return(&p->refs) && orbpf_tfw_cancel_all(p))
		__wait_event(p->exit_waitq, !atomic_read(&p->refs));

	 
	if (p->task_ref)
		put_task_struct(p->task_ref);
	if (p->pgid_ref)
		put_pid(p->pgid_ref);
	if (p->ppid_ref) {
		put_pid(p->ppid_ref);
	}
	iput(p->inode);
	bpf_prog_put(p->prog);
	kfree(p);
	return 0;
}

static const struct file_operations orbpf_tf_fops = {
	.owner = THIS_MODULE,
	.release = orbpf_tf_release
};

static int orbpf_attach_task_finder(struct orbpf_task_finder *t)
{
	struct task_struct *task_ref = NULL;
	struct pid *pgid_ref = NULL;
	struct pid *ppid_ref = NULL;
	struct orbpf_tf_priv *p;
	struct bpf_prog *prog;
	struct inode *inode;
	struct file *filp;
	bool should_wait;
	pid_t tgid = 0;
	pid_t pgid = 0;
	pid_t ppid = 0;
	int fd, ret;

	prog = bpf_prog_get(t->prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->type != BPF_PROG_TYPE_KPROBE) {
		ret = -EINVAL;
		goto put_prog;
	}

	inode = orbpf_get_user_inode(u64_to_user_ptr(t->filename));
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto put_prog;
	}

	if (t->pid > 0) {
		task_ref = orbpf_get_task_by_pid(t->pid);
		if (unlikely(task_ref == NULL)) {
			pr_err("cannot find user-supplied pid %d\n",
			       t->pid);
			ret = -ESRCH;
			goto put_inode;
		}

		 
		if (!t->pid_trace_exec) {
			struct file *exe_file;
			bool matches = false;

			exe_file = get_task_exe_file(task_ref);
			if (exe_file) {
				matches = file_inode(exe_file) == inode;
				fput(exe_file);
			}

			if (!matches) {
				ret = -EINVAL;
				goto put_task_or_pids;
			}
		}

		tgid = task_ref->tgid;

	} else if (t->pid < -1) {
		 
		rcu_read_lock();
		pgid_ref = get_pid(find_vpid(-t->pid));
		rcu_read_unlock();
		if (unlikely(pgid_ref == NULL)) {
			pr_err("cannot find user-supplied pgid %d\n",
			       -t->pid);
			ret = -ESRCH;
			goto put_inode;
		}
		pgid = pid_nr(pgid_ref);
		tgid = -1;

	} else if (t->pid == -1) {
		tgid = -1;
	}

	if (t->ppid > 0) {
		 
		rcu_read_lock();
		ppid_ref = get_pid(find_vpid(t->ppid));
		rcu_read_unlock();
		if (unlikely(ppid_ref == NULL)) {
			pr_err("cannot find user-supplied ppid %d\n",
			       t->ppid);
			ret = -ESRCH;
			goto put_inode;
		}
		ppid = pid_nr(ppid_ref);
	}

	ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		goto put_task_or_pids;

	fd = ret;
	filp = anon_inode_getfile("orbpf-tf", &orbpf_tf_fops, NULL, O_CLOEXEC);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		goto put_fd;
	}

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto put_filp;
	}

	 
	if ((p->task_ref = task_ref))
		p->pid_trace_exec = t->pid_trace_exec;
	p->prog = prog;
	p->inode = inode;
	init_waitqueue_head(&p->exit_waitq);
	INIT_LIST_HEAD(&p->tfw_list);
	spin_lock_init(&p->tfw_list_lock);

	 
	if (task_ref && !t->pid_trace_exec) {
		struct orbpf_tf_work *tfw;

		tfw = kmalloc(sizeof(*tfw), GFP_KERNEL);
		if (!tfw) {
			ret = -ENOMEM;
			goto free_p;
		}

		p->tgid = tgid;
		p->refs = (atomic_t)ATOMIC_INIT(1);
		tfw->task = task_ref;
		orbpf_tfw_init(p, tfw);
		ret = orbpf_task_work_add(task_ref, &tfw->twork);
		if (unlikely(ret != 0)) {
			 
			kfree(tfw);
			goto free_p;
		}

		 
		goto pid_finish;
	}

	p->tgid = tgid;
	p->pgid_ref = pgid_ref;
	p->pgid = pgid;
	p->ppid_ref = ppid_ref;
	p->ppid = ppid;
	init_completion(&p->init_done);
	init_rwsem(&p->init_rwsem);

	






	ret = tracepoint_probe_register(sched_exec_tp, orbpf_exec_cb, p);
	if (ret)
		goto free_p;

	if (!p->pid_trace_exec) {
		ret = tracepoint_probe_register(sched_fork_tp, orbpf_fork_cb, p);
		if (ret)
			goto remove_exec_tp;
	}

	










	mutex_lock(orbpf__tracepoints_mutex);
	



	orbpf_synchronize_sched_expedited();
	down_write(&p->init_rwsem);
	






	rcu_read_lock();
	atomic_set_release(&p->refs, 1);
	orbpf_tf_scan(p, task_ref);

	 
	should_wait = orbpf_tf_init_done(p);
	up_write(&p->init_rwsem);
	rcu_read_unlock();

	




	if (should_wait)
		wait_for_completion(&p->init_done);
	mutex_unlock(orbpf__tracepoints_mutex);

pid_finish:
	 
	filp->private_data = p;
	fd_install(fd, filp);
	return fd;

remove_exec_tp:
	tracepoint_probe_unregister(sched_exec_tp, orbpf_exec_cb, p);
	orbpf_tp_unregister_sync();
free_p:
	kfree(p);
put_filp:
	fput(filp);
put_fd:
	put_unused_fd(fd);
put_task_or_pids:
	if (task_ref)
		put_task_struct(task_ref);
	if (pgid_ref)
		put_pid(pgid_ref);
	if (ppid_ref)
		put_pid(ppid_ref);
put_inode:
	iput(inode);
put_prog:
	bpf_prog_put(prog);
	return ret;
}

long orbpf_trace_ioctl(struct file *filp, unsigned int cmd_nr,
	unsigned int size, void __user *arg)
{
	int err;
	union {
		struct orbpf_kprobe kprobe;
		struct orbpf_uprobe uprobe;
		struct orbpf_perf perf;
		struct orbpf_task_finder tf;
	} d;

	switch (cmd_nr) {
	case ORBPF_IOC_ATTACH_KPROBE_NR:
		{
			struct orbpf_kprobe __user *user_kp = arg;
			err = orbpf_check_uarg_tail_zero(user_kp, sizeof(d.kprobe), size);
			if (err)
				return err;
			size = min_t(u32, size, sizeof(d.kprobe));

			

			memset(&d.kprobe, 0, sizeof(d.kprobe));
			if (copy_from_user(&d.kprobe, user_kp, size))
				return -EFAULT;

			return orbpf_attach_kprobe(&d.kprobe);
		}
	case ORBPF_IOC_ATTACH_UPROBE_NR:
		{
			struct orbpf_uprobe __user *user_up = arg;
			err = orbpf_check_uarg_tail_zero(user_up, sizeof(d.uprobe), size);
			if (err)
				return err;
			size = min_t(u32, size, sizeof(d.uprobe));

			

			memset(&d.uprobe, 0, sizeof(d.uprobe));
			if (copy_from_user(&d.uprobe, user_up, size))
				return -EFAULT;

			return orbpf_attach_uprobe(&d.uprobe);
		}
	case ORBPF_IOC_ATTACH_PERF_NR:
		{
			struct orbpf_perf __user *user_pf = arg;
			err = orbpf_check_uarg_tail_zero(user_pf, sizeof(d.perf), size);
			if (err)
				return err;
			size = min_t(u32, size, sizeof(d.perf));

			

			memset(&d.perf, 0, sizeof(d.perf));
			if (copy_from_user(&d.perf, user_pf, size))
				return -EFAULT;

			return orbpf_attach_perf(&d.perf);
		}
	case ORBPF_IOC_ATTACH_TASK_FINDER_NR:
		{
			struct orbpf_task_finder __user *user_tf = arg;
			err = orbpf_check_uarg_tail_zero(user_tf, sizeof(d.tf), size);
			if (err)
				return err;
			size = min_t(u32, size, sizeof(d.tf));

			

			memset(&d.tf, 0, sizeof(d.tf));
			if (copy_from_user(&d.tf, user_tf, size))
				return -EFAULT;

			return orbpf_attach_task_finder(&d.tf);
		}
	case ORBPF_IOC_PING_NR:
		return 0;
	}

	return -ENOTTY;
}

static void orbpf_tf_tp_find(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "sched_process_exec"))
		sched_exec_tp = tp;
	else if (!strcmp(tp->name, "sched_process_fork"))
		sched_fork_tp = tp;
}

int orbpf_trace_init0(void)
{
	for_each_kernel_tracepoint(orbpf_tf_tp_find, NULL);
	if (!sched_exec_tp || !sched_fork_tp) {
		pr_err("failed to find fork and/or exec tracepoints\n");
		return -ENOENT;
	}

	return 0;
}

const char *orbpf_get_running_prog_label(unsigned int *size_ptr)
{
	struct bpf_prog *prog = this_cpu_read(*pcpu_bpf_programs);
	if (unlikely(prog == NULL)) {
		*size_ptr = 0;
		return NULL;
	}

	*size_ptr = prog->prog_label_len;
	return prog->prog_label;
}

int bpf_pcpu_pcpu_bpf_programs_init0(void) { pcpu_bpf_programs = alloc_percpu(struct bpf_prog *); if (unlikely(pcpu_bpf_programs == NULL)) { return -ENOMEM; } return 0; }
void bpf_pcpu_pcpu_bpf_programs_exit0(void) { free_percpu(pcpu_bpf_programs); }