/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
#ifndef _ORBPF_COMPAT_H_
#define _ORBPF_COMPAT_H_

#include <linux/uaccess.h>
#include <asm/tlbflush.h>
#include <linux/orbpf_conf.h>
#include <linux/fs.h>
#include <linux/task_work.h>
#include <linux/sched/signal.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
#include <linux/fs_pin.h>
#endif  
#include <linux/mm.h>
#include <linux/mount.h>

#ifndef ORBPF_CONF_NMI_UACCESS_OKAY
bool nmi_uaccess_okay(void);
#endif

 
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else  
	int mnt_count;
	int mnt_writers;
#endif  
	struct list_head mnt_mounts;	 
	struct list_head mnt_child;	 
	struct list_head mnt_instance;	 
	const char *mnt_devname;	 
	struct list_head mnt_list;
	struct list_head mnt_expire;	 
	struct list_head mnt_share;	 
	struct list_head mnt_slave_list; 
	struct list_head mnt_slave;	 
	struct mount *mnt_master;	 
	struct mnt_namespace *mnt_ns;	 
	struct mountpoint *mnt_mp;	 
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
	struct hlist_node mnt_mp_list;	 
#else  
	union {
		struct hlist_node mnt_mp_list;	 
		struct hlist_node mnt_umount;
	};
#endif  
	struct list_head mnt_umounting;  
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif  
	int mnt_id;			 
	int mnt_group_id;		 
	int mnt_expiry_mark;		 
	struct hlist_head mnt_pins;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
	struct fs_pin mnt_umount;
	struct dentry *mnt_ex_mountpoint;
#else  
	struct hlist_head mnt_stuck_children;
#endif  
} __randomize_layout;

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

#ifndef __annotate_jump_table
#define __annotate_jump_table
#endif  

#ifndef __nocfi
#define __nocfi
#endif  

#ifndef fallthrough
#if defined(__has_attribute)
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)   
#endif
#else  
#define fallthrough do {} while (0)   
#endif  
#endif  

#ifndef static_assert
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#endif  

#ifndef ENOPARAM
#define ENOPARAM 519
#endif  

#ifndef U32_MIN
#define U32_MIN		((u32)0)
#endif  

#ifndef list_entry_is_head
#define list_entry_is_head(pos, head, member) (&pos->member == (head))
#endif  

#if 1

#define MGL int  
#endif  

#ifndef ORBPF_CONF_SEQ_BPRINTF

#ifdef ORBPF_CONF_BSTR_PRINTF
int bstr_printf(char *buf, size_t size, const char *fmt, const u32 *bin_buf);
#else
#error "No implementation for bstr_printf()"
#endif

#include <linux/seq_file.h>
static inline void seq_bprintf(struct seq_file *m, const char *f,
			       const u32 *binary)
{
	int len;

	if (m->count < m->size) {
		len = bstr_printf(m->buf + m->count, m->size - m->count, f,
				  binary);
		if (m->count + len < m->size) {
			m->count += len;
			return;
		}
	}
	m->count = m->size;  
}

#endif   

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
typedef struct list_head list_cmp_arg_t;
#else  
typedef const struct list_head list_cmp_arg_t;
#endif  

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static inline int path_permission(const struct path *path, int mask)
{
	return inode_permission(d_inode(path->dentry), mask);
}
#define inode_init_owner(a, b, c, d) inode_init_owner((b), (c), (d))
#define inode_permission(a, b, c) inode_permission((b), (c))
#define INODE_OPS_ARG(a)
#else  
#define INODE_OPS_ARG(a) a,
#endif  

#ifndef ORBPF_CONF_GET_RANDOM_INT
static inline unsigned int get_random_int(void)
{
#ifndef ORBPF_CONF_GET_RANDOM_U32
	return get_random_u32();
#elif defined(ORBPF_CONF_GET_RANDOM_U32)
	return (unsigned int) get_random_long();
#else
	#error "No implementation for get_random_int()"
#endif
}
#endif

#ifndef ORBPF_CONF_IRQ_WORK_IS_BUSY
#include <linux/irq_work.h>

static inline bool irq_work_is_busy(struct irq_work *work)
{
#ifdef ORBPF_CONF_IRQ_WORK_ATOMIC_FLAGS
	return atomic_read(&work->flags) & IRQ_WORK_BUSY;
#else
	return work->flags & IRQ_WORK_BUSY;
#endif
}
#endif

#ifdef ORBPF_CONF_SHA1_H

#include <crypto/sha1.h>

#else

#include <crypto/sha.h>

#ifdef ORBPF_CONF_CRYPTOHASH_H
#include <linux/cryptohash.h>
#endif

#if !defined(ORBPF_CONF_SHA_H_SHA1_API_CRYPTOHASH) && \
    !defined(ORBPF_CONF_SHA_H_SHA1_API)
#define SHA1_DIGEST_WORDS SHA_DIGEST_WORDS
#define SHA1_WORKSPACE_WORDS SHA_WORKSPACE_WORDS
#define sha1_init sha_init
#define sha1_transform sha_transform
#endif

#endif   

static inline int
orbpf_task_work_add(struct task_struct *task, struct callback_head *twork)
{
	int rc;

	rc = task_work_add(task, twork,
#ifdef ORBPF_CONF_TWA_SIGNAL_NO_IPI
			     TWA_SIGNAL_NO_IPI
#elif defined(ORBPF_CONF_TWA_SIGNAL)
			     TWA_SIGNAL
#elif defined(ORBPF_CONF_TWA_RESUME)
			     TWA_RESUME
#else
			     true
#endif
			     );
	if (rc != 0) {
		return 0;
	}

#if !defined(ORBPF_CONF_TWA_SIGNAL) && !defined(ORBPF_CONF_TWA_SIGNAL_NO_IPI)
	{
		unsigned long flags;

		if (lock_task_sighand(task, &flags)) {
			signal_wake_up(task, 0);
			unlock_task_sighand(task, &flags);
		}
	}
#endif
	return rc;
}

#ifdef ORBPF_CONF_KERNEL_READ_FILE
#include <linux/kernel_read_file.h>
#endif

#if !defined(ORBPF_CONF_MMAP_LOCK_IS_CONTENDED) && \
    !defined(ORBPF_CONF_MMAP_LOCK_IS_CONTENDED_MM_LOCK_H)
static inline int mmap_lock_is_contended(struct mm_struct *mm)
{
#ifdef ORBPF_CONF_MM_MMAP_LOCK
	return rwsem_is_contended(&mm->mmap_lock);
#else
	return rwsem_is_contended(&mm->mmap_sem);
#endif
}
#endif  

#ifndef ORBPF_CONF_PERFMON_CAPABLE
static inline bool perfmon_capable(void)
{
	return capable(CAP_SYS_ADMIN);
}
#endif

#ifndef ORBPF_CONF_BPF_CAPABLE
static inline bool bpf_capable(void)
{
	return capable(CAP_SYS_ADMIN);
}
#endif
































#ifndef ORBPF_CONF_MMAP_READ_UNLOCK_NON_OWNER
static inline void mmap_read_unlock_non_owner(struct mm_struct *mm)
{
	up_read_non_owner(&mm->mmap_sem);
}
#endif

#ifndef ORBPF_CONF_MIGRATE_DISABLE
static inline void migrate_disable(void)
{
	preempt_disable();
}
#endif

#ifndef ORBPF_CONF_MIGRATE_ENABLE
static inline void migrate_enable(void)
{
	preempt_enable();
}
#endif

#ifndef ORBPF_CONF_CANT_MIGRATE
#define cant_migrate() do { } while (0)
#endif

#ifndef ORBPF_CONF_STRNCPY_FROM_KERNEL_NOFAULT
#ifdef ORBPF_CONF_STRNCPY_FROM_UNSAFE
#define strncpy_from_kernel_nofault(dst, src, len) \
	strncpy_from_unsafe((dst), (src), (len))
#else
#error "No implementation for strncpy_from_kernel_nofault()"
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#ifdef CONFIG_X86_64
#include <asm/tlbflush.h>
#elif defined(CONFIG_ARM64)
enum {
	AARCH64_INSN_HINT_BTIC  = 0x22 << 5,
	AARCH64_INSN_HINT_BTIJ  = 0x24 << 5,
	AARCH64_INSN_HINT_BTIJC = 0x26 << 5
};
#endif  

#define get_kernel_nofault(val, ptr) probe_kernel_address((ptr), (val))

#ifndef ORBPF_CONF_COPY_FROM_KERNEL_NOFAULT
#define copy_from_kernel_nofault(dst, src, len) \
	probe_kernel_read((dst), (src), (len))
#endif

#ifndef ORBPF_CONF_COPY_TO_KERNEL_NOFAULT
#define copy_to_kernel_nofault(dst, src, len) \
	probe_kernel_write((dst), (src), (len))
#endif

#include <linux/vmalloc.h>
#define __vmalloc(len, gfp) __vmalloc((len), (gfp), PAGE_KERNEL)
#endif  

#ifndef ORBPF_CONF_NS_MATCH

#ifdef ORBPF_CONF_NS_COMMON
#include <linux/ns_common.h>
static inline bool ns_match(const struct ns_common *ns, dev_t dev, ino_t ino)
{
	struct vfsmount *nsfs_mnt = orbpf__nsfs_mnt;

	return (ns->inum == ino) && (nsfs_mnt->mnt_sb->s_dev == dev);
}
#endif   

#endif   

#ifndef ORBPF_CONF_ALIGNED_BYTE_MASK
#ifdef __LITTLE_ENDIAN
#define aligned_byte_mask(n) ((1UL << 8*(n))-1)
#else  
#define aligned_byte_mask(n) (~0xffUL << (BITS_PER_LONG - 8 - 8*(n)))
#endif  
#else
#include <linux/bitops.h>
#endif

static inline bool orbpf_access_ok(const void *addr, size_t len)
{
#ifdef ORBPF_CONF_ASM_ACCESS_OK
	return __access_ok(addr, len);
#elif defined(ORBPF_CONF_ACCESS_OK_3_ARGS)
	return access_ok(VERIFY_READ, addr, len);
#else
	return access_ok(addr, len);
#endif
}

static inline bool orbpf_user_access_begin(const void *ptr, size_t size)
{
#ifdef ORBPF_CONF_USER_ACCESS_BEGIN_3_ARGS
    return user_access_begin(VERIFY_READ, ptr, size);
#elif 0 && defined(ORBPF_CONF_USER_ACCESS_BEGIN_2_ARGS)
    return user_access_begin(ptr, size);
#else

     if (unlikely(!orbpf_access_ok(ptr, size)))
	     return 0;

#ifdef CONFIG_X86_64
     __uaccess_begin_nospec();
#define user_access_end()  __uaccess_end()

#else   


#define user_access_end() do { } while (0)
#endif   

    return 1;

#endif
}

#ifndef ORBPF_CONF_CHECK_ZEROED_USER

static inline int check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

	if (unlikely(!orbpf_user_access_begin(from, size)))
		return -EFAULT;

	unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	if (align)
		val &= ~aligned_byte_mask(align);

	while (size > sizeof(unsigned long)) {
		if (unlikely(val))
			goto done;

		from += sizeof(unsigned long);
		size -= sizeof(unsigned long);

		unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	}

	if (size < sizeof(unsigned long))
		val &= aligned_byte_mask(size);

done:
	user_access_end();
	return (val == 0);
err_fault:
	user_access_end();
	return -EFAULT;
}
#endif  

static __always_inline __must_check unsigned long
orbpf_copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
{
	unsigned long res;

#ifdef ORBPF_CONF_INSTRUMENT_COPY_FROM_USER_BEFORE_AFTER
	instrument_copy_from_user_before(to, from, n);
#elif defined(ORBPF_CONF_INSTRUMENT_COPY_FROM_USER)
	instrument_copy_from_user(to, from, n);
#else
	kasan_check_write(to, n);
#endif

#ifdef ORBPF_CONF_RAW_COPY_FROM_USER
	res = raw_copy_from_user(to, from, n);
#else
#error "No implementation for orbpf_copy_from_user_inatomic()"
#endif

#ifdef ORBPF_CONF_INSTRUMENT_COPY_FROM_USER_BEFORE_AFTER
	instrument_copy_from_user_after(to, from, n, res);
#endif
	return res;
}

static inline long orbpf_copy_from_user_nofault(void *dst, const void __user *src,
	size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return copy_from_user_nofault(dst, src, size);
#else
	

	long ret = -EFAULT;
        unsigned long max_addr, src_addr;

	if (unlikely(size == 0))
		return 0;

        max_addr = TASK_SIZE_MAX;
#ifdef ORBPF_CONF_UNTAGGED_ADDR
        src_addr = (unsigned long)untagged_addr(src);
#else
        src_addr = (unsigned long)src;
#endif
        if (unlikely(src_addr < PAGE_SIZE || src_addr + size > max_addr)) {
		return ret;
	}

	if (unlikely(!nmi_uaccess_okay()))
		return ret;

	if (!orbpf_user_access_begin(src, size))
		return ret;

	pagefault_disable();
	ret = orbpf_copy_from_user_inatomic(dst, src, size) ? -EFAULT : 0;
	pagefault_enable();

	user_access_end();

	return ret;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)

#ifndef IS_UNALIGNED
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define IS_UNALIGNED(src, dst)  0
#else
#define IS_UNALIGNED(src, dst)  \
        (((long) dst | (long) src) & (sizeof(long) - 1))
#endif
#endif

#include <asm/word-at-a-time.h>

static __always_inline long orbpf_do_strncpy_from_user(char *dst, const char __user *src,
                                        unsigned long count, unsigned long max)
{
	unsigned long res = 0;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

        if (IS_UNALIGNED(src, dst))
                goto byte_at_a_time;

        while (max >= sizeof(unsigned long)) {
		unsigned long c, data, mask;

		 
		unsafe_get_user(c, (unsigned long __user *)(src+res), byte_at_a_time);

		










		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			mask = zero_bytemask(data);
			*(unsigned long *)(dst+res) = c & mask;
			return res + find_zero(data);
		}

                *(unsigned long *)(dst+res) = c;

                res += sizeof(unsigned long);
                max -= sizeof(unsigned long);
        }

byte_at_a_time:
        while (max) {
                char c;

                unsafe_get_user(c,src+res, efault);
                dst[res] = c;
                if (!c)
                        return res;
                res++;
                max--;
        }

        



        if (res >= count)
                return res;

        



efault:
        return -EFAULT;
}

static __always_inline long orbpf_strncpy_from_user(char *dst, const char __user *src, long count)
{
        unsigned long max_addr, src_addr;

        if (unlikely(count <= 0))
                return 0;

        max_addr = TASK_SIZE_MAX;
#ifdef ORBPF_CONF_UNTAGGED_ADDR
        src_addr = (unsigned long)untagged_addr(src);
#else
        src_addr = (unsigned long)src;
#endif
        if (likely(src_addr < max_addr)) {
                unsigned long max = max_addr - src_addr;
                long retval;

                



                if (max > count)
                        max = count;

		kasan_check_write(dst, count);
		if (orbpf_user_access_begin(src, max)) {
			retval = orbpf_do_strncpy_from_user(dst, src, count, max);
			user_access_end();
			return retval;
		}
        }
        return -EFAULT;
}
#endif

static inline long orbpf_strncpy_from_user_nofault(char *dst,
					    const void __user *unsafe_addr,
					    long count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return strncpy_from_user_nofault(dst, unsafe_addr, count);
#else
	

	long ret = -EFAULT;
        unsigned long max_addr, src_addr;

	if (unlikely(count <= 0))
		return 0;

        max_addr = TASK_SIZE_MAX;
#ifdef ORBPF_CONF_UNTAGGED_ADDR
        src_addr = (unsigned long)untagged_addr(unsafe_addr);
#else
        src_addr = (unsigned long)unsafe_addr;
#endif
        if (unlikely(src_addr < PAGE_SIZE || src_addr + count > max_addr)) {
		return ret;
	}

	if (unlikely(!nmi_uaccess_okay()))
		return ret;

	pagefault_disable();
	ret = orbpf_strncpy_from_user(dst, unsafe_addr, count);
	pagefault_enable();

	if (ret >= count) {
		ret = count;
		dst[ret - 1] = '\0';
	} else if (ret > 0) {
		ret++;
	}

	return ret;
#endif
}

#include <linux/rcupdate.h>

static inline void orbpf_synchronize_sched(void)
{
#ifdef ORBPF_CONF_SYNCHRONIZE_SCHED
	synchronize_sched();
#elif defined(ORBPF_CONF_SYNCHRONIZE_RCU)
	synchronize_rcu();
#else
#error "No implementation for orbpf_synchronize_sched!"
#endif
}

static inline void orbpf_synchronize_sched_expedited(void)
{
#ifdef ORBPF_CONF_SYNCHRONIZE_SCHED_EXPEDITED
	synchronize_sched_expedited();
#elif defined(ORBPF_CONF_SYNCHRONIZE_RCU_EXPEDITED)
	synchronize_rcu_expedited();
#else
#error "No implementation for orbpf_synchronize_sched_expedited!"
#endif
}

#ifndef ORBPF_CONF_POLL_T
typedef unsigned __bitwise __poll_t;
#endif

#ifndef ORBPF_CONF_SIZEOF_FIELD
#define sizeof_field(t, f) (sizeof(((t*)0)->f))
#endif

#ifndef ORBPF_CONF_EPOLL_EV_MASKS

#ifndef EPOLLIN
#define EPOLLIN     0x00000001
#endif

#ifndef EPOLLERR
#define EPOLLERR       0x00000008
#endif

#ifndef EPOLLRDNORM
#define EPOLLRDNORM 0x00000040
#endif

#endif   

#ifndef ORBPF_CONF_ARRAY_SIZE
#define array_size(n, size)  ((n)*(size))
#else
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#endif

#ifndef ORBPF_CONF_ATOMIC64_FETCH_ADD_UNLESS

#ifndef ORBPF_CONF_ATOMIC64_TRY_CMPXCHG
#ifndef atomic64_try_cmpxchg
static __always_inline bool
atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
{
        s64 r, o = *old;
            r = atomic64_cmpxchg(v, o, new);
                if (unlikely(r != o))
                            *old = r;
                    return likely(r == o);
}
#define atomic64_try_cmpxchg atomic64_try_cmpxchg
#endif
#endif

static __always_inline s64
atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
{
    s64 c = atomic64_read(v);

    do {
        if (unlikely(c == u))
            break;
    } while (!atomic64_try_cmpxchg(v, &c, c + a));

    return c;
}

#endif   

#ifdef ORBPF_CONF_KVCALLOC_SLAB_H
#include <linux/slab.h>
#endif

#if !defined(ORBPF_CONF_KVCALLOC) && !defined(ORBPF_CONF_KVCALLOC_SLAB_H)
static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	void *ret;
	size_t len = n * size;

	 
	if (n && len / n != size)
		return NULL;

	ret = kvmalloc(len, flags);
	if (ret)
		memset(ret, 0, len);

	return ret;
}
#endif   

#ifndef ORBPF_CONF_KTIME_GET_COARSE
static inline ktime_t ktime_get_coarse(void)
{
#ifdef ORBPF_CONF_KTIME_GET_COARSE_TS64
	struct timespec64 ts;

	ktime_get_coarse_ts64(&ts);
	return timespec64_to_ktime(ts);
#else
    return (ktime_t) KTIME_MAX;
#endif
}

 
static inline u64 ktime_get_coarse_ns(void)
{
	return ktime_to_ns(ktime_get_coarse());
}

#endif   

#ifndef ORBPF_CONF_KTIME_GET_BOOTTIME_NS
#define ktime_get_boottime_ns() ktime_get_boot_ns()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
 
#include <linux/string.h>
static inline char *compat_strnchr(const char *s, size_t count, int c)
{
	while (count--) {
		if (*s == (char)c)
			return (char *)s;
		if (*s++ == '\0')
			break;
	}
	return NULL;
}
#define strnchr(a, b, c) compat_strnchr((a), (b), (c))
#endif  

#ifndef ORBPF_CONF_LOCKDEP_REGISTER_KEY
#define lockdep_register_key(a) do { } while (0)
#define lockdep_unregister_key(a) do { } while (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#endif  

#if 1
#define orbpf_btf_member_bit_offset  btf_member_bit_offset
#define orbpf_btf_member_bitfield_size  btf_member_bitfield_size
#define orbpf_check_and_init_map_lock  check_and_init_map_lock
#define orbpf_copy_map_value_locked  copy_map_value_locked
#define orbpf_copy_map_value  copy_map_value
#define orbpf_map_value_has_spin_lock  map_value_has_spin_lock
#endif

#ifndef ORBPF_CONF_VM_FLAGS_CLEAR
static inline void vm_flags_clear(struct vm_area_struct *vma,
                                 vm_flags_t flags)
{
	vma->vm_flags &= ~flags;
}
#endif

#endif  