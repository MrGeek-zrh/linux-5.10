/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RMAP_H
#define _LINUX_RMAP_H
/*
 * Declarations for Reverse Mapping functions in mm/rmap.c
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/memcontrol.h>
#include <linux/highmem.h>

/*
 * The anon_vma heads a list of private "related" vmas, to scan if
 * an anonymous page pointing to this anon_vma needs to be unmapped:
 * the vmas on the list will be related by forking, or by splitting.
 *
 * Since vmas come and go as they are split and merged (particularly
 * in mprotect), the mapping field of an anonymous page cannot point
 * directly to a vma: instead it points to an anon_vma, on whose list
 * the related vmas can be easily linked or unlinked.
 *
 * After unlinking the last vma on the list, we must garbage collect
 * the anon_vma object itself: we're guaranteed no page can be
 * pointing to this anon_vma once its vma list is empty.
 *
 * 链接 物理页面 的 page 数据结构 和 VMA 的 vm_area_struct 数据结构，
 *
 * 指向本数据结构的对象：
 * -----------------------------------------
 * vm_area_struct->anon_vma ->
 * page->mapping(匿名页面时) ->
 *
 *     vma
 * +----------+
 * |          |
 * +----------+
 * | anon_vma |-------------+
 * +----------+             |
 * |          |             |            anon_vma
 * +----------+             +---------->+--------+
 *                          |           |        |
 *                          |           +--------+          anon_vma 红黑树
 *     page                 |           |  root  |-------->    ()
 * +----------+             |           +--------+             /\
 * |          |             |           |        |           ()  ()
 * +----------+             |           +--------+           /\  /\
 * |  mapping |-------------+                              () ()() ()
 * +----------+
 * |          |
 * +----------+
 */
/*
 * struct anon_vma - 匿名虚拟内存区域的核心数据结构
 *
 * 主要作用:
 * 1. 实现反向映射(RMAP)机制
 *    - 通过page->mapping找到anon_vma
 *    - 通过anon_vma找到所有映射该页面的VMA
 *    - 用于页面回收时快速定位使用者
 *
 * 2. 支持写时复制(COW)
 *    - 父进程fork时子进程共享父进程的物理页面
 *    - 写入时复制新页面并更新映射关系
 *    - 通过anon_vma树状结构维护父子关系
 *
 * 3. 树状层级结构
 *    root     - 指向树的根节点
 *    parent   - 指向父anon_vma
 *    degree   - 子anon_vma和VMA的数量
 *
 * 4. 引用计数和同步
 *    refcount - 引用计数,保护结构体生命周期
 *    rwsem    - 读写信号量,保护内部字段访问
 *
 * 5. 典型应用场景
 *    - fork()时继承父进程的映射关系
 *    - 内存回收扫描页面使用情况
 *    - 页面迁移时更新映射关系
 */
struct anon_vma { /* 匿名 VMA */

    /* 指向 根节点 */
    struct anon_vma *root; /* Root of this anon_vma tree */

    /**
     *  保护链表
     *
     *  写保护见 `anon_vma_fork()` 函数中的 `anon_vma_lock_write()``anon_vma_unlock_write()`
     *  读保护见 `try_to_unmap()` 函数中的 `page_lock_anon_vma_read()`回调函数
     *                                      `down_read_trylock()``anon_vma_unlock_read()`
     */
    struct rw_semaphore rwsem; /* W: modification, R: walking the list */
    /*
	 * The refcount is taken on an anon_vma when there is no
	 * guarantee that the vma of page			 * Most pages have a mapping and most filesystems
			 * provide a migratepage callback. Anonymous pages
			 * are part of swap space which also has its own
			 * migratepage callback. This is the most common path
			 * for page migration.gew
 the duration of the operation. A caller that takes
	 * the reference is responsible for clearing up the
	 * anon_vma if they are the last user on release
	 *
	 * 引用计数
	 *  =0 时,将被释放，见`__put_anon_vma()`
	 *
	 */
    atomic_t refcount;

    /*
	 * Count of child anon_vmas and VMAs which points to this anon_vma.
	 *
	 * This counter is used for making decision about reusing anon_vma
	 * instead of forking new one. See comments in function anon_vma_clone.
	 *
	 * 决定是否在 fork/clone 时复用 anon_vma 结构
	 * degree < 2: 将复用
	 */
    unsigned degree;

    /**
     *  指向 父节点
     *
     *  `anon_vma_fork()` 指向了 父进程的 aon_vma
     *  `anon_vma_alloc()`指向 结构本身
     */
    struct anon_vma *parent; /* Parent of this anon_vma */

    /*
	 * NOTE: the LSB of the rb_root.rb_node is set by
	 * mm_take_all_locks() _after_ taking the above lock. So the
	 * rb_root must only be read/written after taking the above lock
	 * to be sure to see a valid next pointer. The LSB bit itself
	 * is serialized by a system wide lock only visible to
	 * mm_take_all_locks() (mm_all_locks_mutex).
	 */

    /* Interval tree of private "related" vmas */
    struct rb_root_cached rb_root; /* anon_vma_chain->rb */
};

/*
 * The copy-on-write semantics of fork mean that an anon_vma
 * can become associated with multiple processes. Furthermore,
 * each child process will have its own anon_vma, where new
 * pages for that process are instantiated.
 *
 * This structure allows us to find the anon_vmas associated
 * with a VMA, or the VMAs associated with an anon_vma.
 * The "same_vma" list contains the anon_vma_chains linking
 * all the anon_vmas associated with this VMA.
 * The "rb" field indexes on an interval tree the anon_vma_chains
 * which link all the VMAs associated with this anon_vma.
 *
 * 该数据结构起到枢纽作用，比如：
 *  1. 链接父子进程间的 struct anon_vma 结构
 */
struct anon_vma_chain {
    /* 指向 VMA */
    struct vm_area_struct *vma;

    /* 可以指向 父进程或子进程 的 anon_vma 结构 */
    struct anon_vma *anon_vma;

    /**
     *  链表节点，该链表具有相同的 VMA 结构
     *  链表头是：
     *
     *  vm_area_struct->anon_vma_chain
     */
    struct list_head same_vma; /* locked by mmap_lock & page_table_lock */

    struct rb_node rb; /* locked by anon_vma->rwsem */
    unsigned long rb_subtree_last;

#ifdef CONFIG_DEBUG_VM_RB
    unsigned long cached_vma_start, cached_vma_last;
#endif
};

// 用于控制unmap的行为
// ttu: try to unmap
enum ttu_flags {
    /* migration mode */ // 迁移场景下使用
    TTU_MIGRATION = 0x1,
    /* munlock mode */ // munlock场景下使用
    // munlock 对应与mlock?
    // mlock 函数可以将指定的内存页面锁定在物理内存中，防止它们被交换到磁盘上.
    TTU_MUNLOCK = 0x2,

    /* split huge PMD if any */ // 如果存在huge PMD，则进行拆分
    TTU_SPLIT_HUGE_PMD = 0x4,
    /* ignore mlock */ // 忽略mlock状态的标志
    TTU_IGNORE_MLOCK = 0x8,
    /* corrupted page is recoverable */ // 损坏的页面是可恢复的
    TTU_IGNORE_HWPOISON = 0x20,
    // 批量刷新TLB
    TTU_BATCH_FLUSH = 0x40, /* Batch TLB flushes where possible
					 * and caller guarantees they will
					 * do a final flush if necessary */
    // 不需要获取rmap锁
    TTU_RMAP_LOCKED = 0x80, /* do not grab rmap lock:
					 * caller holds it */
    // 在拆分透明大页时冻结pte,不允许被访问
    TTU_SPLIT_FREEZE = 0x100,
    /* freeze pte under splitting thp */
};

#ifdef CONFIG_MMU
static inline void get_anon_vma(struct anon_vma *anon_vma)
{
    atomic_inc(&anon_vma->refcount);
}

void __put_anon_vma(struct anon_vma *anon_vma);

static inline void put_anon_vma(struct anon_vma *anon_vma)
{
    if (atomic_dec_and_test(&anon_vma->refcount))
        __put_anon_vma(anon_vma);
}

static inline void anon_vma_lock_write(struct anon_vma *anon_vma)
{
    down_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_write(struct anon_vma *anon_vma)
{
    up_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
{
    down_read(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_read(struct anon_vma *anon_vma)
{
    up_read(&anon_vma->root->rwsem);
}

/*
 * anon_vma helper functions.
 */
void anon_vma_init(void); /* create anon_vma_cachep */
int __anon_vma_prepare(struct vm_area_struct *);
void unlink_anon_vmas(struct vm_area_struct *);
int anon_vma_clone(struct vm_area_struct *, struct vm_area_struct *);
int anon_vma_fork(struct vm_area_struct *, struct vm_area_struct *);

/**
 *  RMAP 相关结构申请
 *
 *
 */
static inline int anon_vma_prepare(struct vm_area_struct *vma)
{
    if (likely(vma->anon_vma)) /* 已经申请了 anon_vma 结构 */
        return 0;

    return __anon_vma_prepare(vma); /* 申请 */
}

static inline void anon_vma_merge(struct vm_area_struct *vma, struct vm_area_struct *next)
{
    VM_BUG_ON_VMA(vma->anon_vma != next->anon_vma, vma);
    unlink_anon_vmas(next);
}

struct anon_vma *page_get_anon_vma(struct page *page);

/* bitflags for do_page_add_anon_rmap() */
#define RMAP_EXCLUSIVE 0x01
#define RMAP_COMPOUND 0x02

/*
 * rmap interfaces called when adding or removing pte of page
 */
void page_move_anon_rmap(struct page *, struct vm_area_struct *);
void page_add_anon_rmap(struct page *, struct vm_area_struct *, unsigned long, bool);
void do_page_add_anon_rmap(struct page *, struct vm_area_struct *, unsigned long, int);
void page_add_new_anon_rmap(struct page *, struct vm_area_struct *, unsigned long, bool);
void page_add_file_rmap(struct page *, bool);
void page_remove_rmap(struct page *, bool);

void hugepage_add_anon_rmap(struct page *, struct vm_area_struct *, unsigned long);
void hugepage_add_new_anon_rmap(struct page *, struct vm_area_struct *, unsigned long);

static inline void page_dup_rmap(struct page *page, bool compound)
{
    atomic_inc(compound ? compound_mapcount_ptr(page) : &page->_mapcount);
}

/*
 * Called from mm/vmscan.c to handle paging out
 */
int page_referenced(struct page *, int is_locked, struct mem_cgroup *memcg, unsigned long *vm_flags);

bool try_to_unmap(struct page *, enum ttu_flags flags);

/* Avoid racy checks */
#define PVMW_SYNC (1 << 0)
/* Look for migarion entries rather than present PTEs */
#define PVMW_MIGRATION (1 << 1)

/**
 *
 */
struct page_vma_mapped_walk {
    struct page *page;
    struct vm_area_struct *vma;
    unsigned long address;
    pmd_t *pmd;
    pte_t *pte;
    spinlock_t *ptl;
    unsigned int flags;
};

static inline void page_vma_mapped_walk_done(struct page_vma_mapped_walk *pvmw)
{
    if (pvmw->pte)
        pte_unmap(pvmw->pte);
    if (pvmw->ptl)
        spin_unlock(pvmw->ptl);
}

bool page_vma_mapped_walk(struct page_vma_mapped_walk *pvmw);

/*
 * Used by swapoff to help locate where page is expected in vma.
 */
unsigned long page_address_in_vma(struct page *, struct vm_area_struct *);

/*
 * Cleans the PTEs of shared mappings.
 * (and since clean PTEs should also be readonly, write protects them too)
 *
 * returns the number of cleaned PTEs.
 */
int page_mkclean(struct page *);

/*
 * called in munlock()/munmap() path to check for other vmas holding
 * the page mlocked.
 */
void try_to_munlock(struct page *);

void remove_migration_ptes(struct page *old, struct page *new, bool locked);

/*
 * Called by memory-failure.c to kill processes.
 */
struct anon_vma *page_lock_anon_vma_read(struct page *page);
void page_unlock_anon_vma_read(struct anon_vma *anon_vma);
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma);

typedef struct anon_vma *anon_vma_t; /* +++ */

/*
 * rmap_walk_control: To control rmap traversing for specific needs
 *
 * arg: passed to rmap_one() and invalid_vma()
 * rmap_one: executed on each vma where page is mapped
 * done: for checking traversing termination condition
 * anon_lock: for getting anon_lock by optimized way rather than default
 * invalid_vma: for skipping uninterested vma
 */

/* arg: 传递给 rmap_one() 和 invalid_vma()                    │
│   * rmap_one: 在每个映射页面的虚拟内存区域（vma）上执行        │
│   * done: 用于检查遍历终止条件                                 │
│   * anon_lock: 以优化的方式获取匿名锁，而不是默认方式          │
│   * invalid_vma: 用于跳过不感兴趣的虚拟内存区域（vma）         │
 */
struct rmap_walk_control {
    /* 下面回调函数的 argument */
    void *arg;
    /*
	 * Return false if page table scanning in rmap_walk should be stopped.
	 * Otherwise, return true.
	 *
	 * 如果 页表 扫描应该被停止，返回 false，否则 返回 true
	 */
    bool (*rmap_one)(struct page *page, struct vm_area_struct *vma, unsigned long addr, void *arg);

    /* 完成 */
    int (*done)(struct page *page);

    anon_vma_t (*anon_lock)(struct page *page);

    /* 可用 */
    bool (*invalid_vma)(struct vm_area_struct *vma, void *arg);
};

void rmap_walk(struct page *page, struct rmap_walk_control *rwc);
void rmap_walk_locked(struct page *page, struct rmap_walk_control *rwc);

#else /* !CONFIG_MMU */

#endif /* CONFIG_MMU */

#endif /* _LINUX_RMAP_H */
