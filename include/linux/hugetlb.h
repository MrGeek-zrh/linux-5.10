/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUGETLB_H
#define _LINUX_HUGETLB_H

#include <linux/mm_types.h>
#include <linux/mmdebug.h>
#include <linux/fs.h>
#include <linux/hugetlb_inline.h>
#include <linux/cgroup.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/pgtable.h>
#include <linux/gfp.h>

struct ctl_table;
struct user_struct;
struct mmu_gather;

#ifndef is_hugepd
typedef struct {
    unsigned long pd;
} hugepd_t;
#define is_hugepd(hugepd) (0)
#define __hugepd(x) ((hugepd_t) { (x) })
#endif

#ifdef CONFIG_HUGETLB_PAGE

#include <linux/mempolicy.h>
#include <linux/shm.h>
#include <asm/tlbflush.h>

/*
 * struct hugepage_subpool - 管理大页子池的数据结构
 * @lock: 保护子池数据的自旋锁
 * @count: 引用计数 
 * @max_hpages: 子池允许分配的最大大页数量,-1表示无限制
 * @used_hpages: 已使用的大页数量,包含已分配和预留的页面
 * @hstate: 指向hugeTLB状态对象,描述大页的大小等属性
 * @min_hpages: 子池需要维护的最小大页数量,-1表示无限制
 * @rsv_hpages: 从全局池中预留的大页数量,用于保证最小大页数量要求
 */
struct hugepage_subpool {
    spinlock_t lock;
    long count;
    long max_hpages; /* 最大可分配大页数,-1表示无限制 */
    long used_hpages; /* 已使用大页总数,包含分配和预留 */
    struct hstate *hstate;
    long min_hpages; /* 最小需要维护的大页数,-1表示无限制 */
    long rsv_hpages; /* 从全局池预留的大页数量 */
};

/*
 * struct resv_map - 管理大页预留映射的数据结构
 * 作用:
 * 1. 跟踪文件映射中大页的预留和分配状态
 * 2. 管理预留区域的生命周期
 * 3. 支持cgroup资源控制
 */
struct resv_map {
    struct kref refs; /* 引用计数 */
    spinlock_t lock; /* 保护resv_map数据的自旋锁 */
    struct list_head regions; /* 预留区域链表 */
    long adds_in_progress; /* 正在进行的添加操作计数 */
    struct list_head region_cache; /* 缓存的region结构链表 */
    long region_cache_count; /* 缓存的region数量 */
#ifdef CONFIG_CGROUP_HUGETLB
    /*
     * 私有映射的预留计数器:
     * - reservation_counter为0表示共享映射或未启用cgroup
     * - pages_per_hpage记录每个大页包含的基页数
     * - css指向cgroup子系统状态
     */
    struct page_counter *reservation_counter;
    unsigned long pages_per_hpage;
    struct cgroup_subsys_state *css;
#endif
};

/*
 * Region tracking -- allows tracking of reservations and instantiated pages
 *                    across the pages in a mapping.
 *
 * The region data structures are embedded into a resv_map and protected
 * by a resv_map's lock.  The set of regions within the resv_map represent
 * reservations for huge pages, or huge pages that have already been
 * instantiated within the map.  The from and to elements are huge page
 * indicies into the associated mapping.  from indicates the starting index
 * of the region.  to represents the first index past the end of  the region.
 *
 * For example, a file region structure with from == 0 and to == 4 represents
 * four huge pages in a mapping.  It is important to note that the to element
 * represents the first element past the end of the region. This is used in
 * arithmetic as 4(to) - 0(from) = 4 huge pages in the region.
 *
 * Interval notation of the form [from, to) will be used to indicate that
 * the endpoint from is inclusive and to is exclusive.
 */
struct file_region {
    struct list_head link;
    long from;
    long to;
#ifdef CONFIG_CGROUP_HUGETLB
    /*
	 * On shared mappings, each reserved region appears as a struct
	 * file_region in resv_map. These fields hold the info needed to
	 * uncharge each reservation.
	 */
    struct page_counter *reservation_counter;
    struct cgroup_subsys_state *css;
#endif
};

extern struct resv_map *resv_map_alloc(void);
void resv_map_release(struct kref *ref);

extern spinlock_t hugetlb_lock;
extern int __read_mostly hugetlb_max_hstate;
#define for_each_hstate(h) for ((h) = hstates; (h) < &hstates[hugetlb_max_hstate]; (h)++)

struct hugepage_subpool *hugepage_new_subpool(struct hstate *h, long max_hpages, long min_hpages);
void hugepage_put_subpool(struct hugepage_subpool *spool);

void reset_vma_resv_huge_pages(struct vm_area_struct *vma);
int hugetlb_sysctl_handler(struct ctl_table *, int, void *, size_t *, loff_t *);
int hugetlb_overcommit_handler(struct ctl_table *, int, void *, size_t *, loff_t *);
int hugetlb_treat_movable_handler(struct ctl_table *, int, void *, size_t *, loff_t *);
int hugetlb_mempolicy_sysctl_handler(struct ctl_table *, int, void *, size_t *, loff_t *);

int copy_hugetlb_page_range(struct mm_struct *, struct mm_struct *, struct vm_area_struct *);
long follow_hugetlb_page(struct mm_struct *, struct vm_area_struct *, struct page **, struct vm_area_struct **,
                         unsigned long *, unsigned long *, long, unsigned int, int *);
void unmap_hugepage_range(struct vm_area_struct *, unsigned long, unsigned long, struct page *);
void __unmap_hugepage_range_final(struct mmu_gather *tlb, struct vm_area_struct *vma, unsigned long start,
                                  unsigned long end, struct page *ref_page);
void __unmap_hugepage_range(struct mmu_gather *tlb, struct vm_area_struct *vma, unsigned long start, unsigned long end,
                            struct page *ref_page);
void hugetlb_report_meminfo(struct seq_file *);
int hugetlb_report_node_meminfo(char *buf, int len, int nid);
void hugetlb_show_meminfo(void);
unsigned long hugetlb_total_pages(void);
vm_fault_t hugetlb_fault(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, unsigned int flags);
int hugetlb_mcopy_atomic_pte(struct mm_struct *dst_mm, pte_t *dst_pte, struct vm_area_struct *dst_vma,
                             unsigned long dst_addr, unsigned long src_addr, struct page **pagep);
int hugetlb_reserve_pages(struct inode *inode, long from, long to, struct vm_area_struct *vma, vm_flags_t vm_flags);
long hugetlb_unreserve_pages(struct inode *inode, long start, long end, long freed);
bool isolate_huge_page(struct page *page, struct list_head *list);
void putback_active_hugepage(struct page *page);
void move_hugetlb_state(struct page *oldpage, struct page *newpage, int reason);
void free_huge_page(struct page *page);
void hugetlb_fix_reserve_counts(struct inode *inode);
extern struct mutex *hugetlb_fault_mutex_table;
u32 hugetlb_fault_mutex_hash(struct address_space *mapping, pgoff_t idx);

pte_t *huge_pmd_share(struct mm_struct *mm, unsigned long addr, pud_t *pud);

struct address_space *hugetlb_page_mapping_lock_write(struct page *hpage);

extern int sysctl_hugetlb_shm_group;
extern struct list_head huge_boot_pages;

/* arch callbacks */

pte_t *huge_pte_alloc(struct mm_struct *mm, unsigned long addr, unsigned long sz);
pte_t *huge_pte_offset(struct mm_struct *mm, unsigned long addr, unsigned long sz);
int huge_pmd_unshare(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long *addr, pte_t *ptep);
void adjust_range_if_pmd_sharing_possible(struct vm_area_struct *vma, unsigned long *start, unsigned long *end);
struct page *follow_huge_addr(struct mm_struct *mm, unsigned long address, int write);
struct page *follow_huge_pd(struct vm_area_struct *vma, unsigned long address, hugepd_t hpd, int flags, int pdshift);
struct page *follow_huge_pmd(struct mm_struct *mm, unsigned long address, pmd_t *pmd, int flags);
struct page *follow_huge_pud(struct mm_struct *mm, unsigned long address, pud_t *pud, int flags);
struct page *follow_huge_pgd(struct mm_struct *mm, unsigned long address, pgd_t *pgd, int flags);

int pmd_huge(pmd_t pmd);
int pud_huge(pud_t pud);
unsigned long hugetlb_change_protection(struct vm_area_struct *vma, unsigned long address, unsigned long end,
                                        pgprot_t newprot);

bool is_hugetlb_entry_migration(pte_t pte);

#else /* !CONFIG_HUGETLB_PAGE */

#endif /* !CONFIG_HUGETLB_PAGE */
/*
 * hugepages at page global directory. If arch support
 * hugepages at pgd level, they need to define this.
 */
#ifndef pgd_huge
#define pgd_huge(x) 0
#endif
#ifndef p4d_huge
#define p4d_huge(x) 0
#endif

#ifndef pgd_write
static inline int pgd_write(pgd_t pgd)
{
    BUG();
    return 0;
}
#endif

#define HUGETLB_ANON_FILE "anon_hugepage"

enum {
    /*
	 * The file will be used as an shm file so shmfs accounting rules
	 * apply
	 */
    HUGETLB_SHMFS_INODE = 1,
    /*
	 * The file is being created on the internal vfs mount and shmfs
	 * accounting rules do not apply
	 */
    HUGETLB_ANONHUGE_INODE = 2,
};

#ifdef CONFIG_HUGETLBFS
/*
 * struct hugetlbfs_sb_info - hugetlbfs superblock的私有数据信息
 * 作用: 保存hugetlbfs文件系统的管理信息和运行时状态
 * 主要用于:
 * 1. inode数量的管理和控制 
 * 2. 存储hugetlb页面状态信息(hstate)
 * 3. 管理文件系统安全权限
 */
struct hugetlbfs_sb_info {
    long max_inodes; /* 最大允许的inode数量 */
    long free_inodes; /* 当前可用(空闲)的inode数量 */
    spinlock_t stat_lock; /* 保护hugetlbfs统计信息的自旋锁 */
    struct hstate *hstate; /* 指向管理大页状态的hstate结构体 */
    struct hugepage_subpool *spool; /* 大页子池指针 */
    kuid_t uid; /* 文件系统所有者的用户ID */
    kgid_t gid; /* 文件系统所有者的组ID */
    umode_t mode; /* 文件系统的访问权限模式 */
};

static inline struct hugetlbfs_sb_info *HUGETLBFS_SB(struct super_block *sb)
{
    return sb->s_fs_info; /* hugetlb在 inode->superblock中的私有数据为  hugetlbfs */
}

struct hugetlbfs_inode_info {
    struct shared_policy policy;
    struct inode vfs_inode;
    unsigned int seals;
};

static inline struct hugetlbfs_inode_info *HUGETLBFS_I(struct inode *inode)
{
    return container_of(inode, struct hugetlbfs_inode_info, vfs_inode);
}

extern const struct file_operations hugetlbfs_file_operations;
extern const struct vm_operations_struct hugetlb_vm_ops;
struct file *hugetlb_file_setup(const char *name, size_t size, vm_flags_t acct, struct user_struct **user,
                                int creat_flags, int page_size_log);

static inline bool is_file_hugepages(struct file *file)
{
    /* 打开的文件 操作符 是大页内存操作符 */
    if (file->f_op == &hugetlbfs_file_operations)
        return true;

    /* 共享内存 */
    return is_file_shm_hugepages(file);
}

static inline struct hstate *hstate_inode(struct inode *i) /* 从inode到 hugetlb superblock */
{
    return HUGETLBFS_SB(i->i_sb)->hstate;
}
#else /* !CONFIG_HUGETLBFS */

#endif /* !CONFIG_HUGETLBFS */

#ifdef HAVE_ARCH_HUGETLB_UNMAPPED_AREA
unsigned long hugetlb_get_unmapped_area(struct file *file, unsigned long addr, unsigned long len, unsigned long pgoff,
                                        unsigned long flags);
#endif /* HAVE_ARCH_HUGETLB_UNMAPPED_AREA */

#ifdef CONFIG_HUGETLB_PAGE

#define HSTATE_NAME_LEN 32
/*
 * struct hstate: 管理单个大页类型(如2MB或1GB)的所有状态信息
 * 主要作用:
 * 1. 定义大页的基本属性(大小、对齐等)
 * 2. 跟踪大页的分配和使用情况
 * 3. 管理NUMA节点上的大页分布
 * 4. 提供大页资源控制
 */
/* Defines one hugetlb page size */
struct hstate { /* hugetlb 页 size */
    /*下一个可分配内存 NUMA NODE */
    int next_nid_to_alloc;
    int next_nid_to_free; // 下一个可以回收内存的 NUMA NODE 节点

    /* 大页的order,决定大页大小 = PAGE_SIZE << order */
    unsigned int order;

    /* 大页掩码,用于地址对齐 */
    unsigned long mask;

    /* 内存池子中固定大页的数量. */
    // 所谓固定就是系统一开始就分配好的大页，不是后期运行时动态申请的
    unsigned long max_huge_pages;
    /* 当前系统中该类型的大页的总数 */
    // 这个包含系统一开始固定分配的大页 和 后期动态申请的大页
    // 为什么是固定分配的大页+动态申请的？
    // 因为只有固定分配的大页使用完了以后，才是动态申请？
    unsigned long nr_huge_pages;
    /* 空闲大页数 */
    // 空闲是指未被使用的，包括 可被使用但没使用 和 预留用作特殊目的的
    unsigned long free_huge_pages;
    unsigned long resv_huge_pages; /* 预留的大页数 */
    /* 通过超发机制动态分配的大页数量 */
    unsigned long surplus_huge_pages;
    /* 可以超发的最多数量*/
    unsigned long nr_overcommit_huge_pages;

    // 处于激活状态的大页链表
    // 激活状态是指预留的大页被使用以后，会变为激活状态:第一个尾页的PG_private标志被设置
    // 除了这个，正在被使用的应该也可以被称为激活状态？是的
    struct list_head hugepage_activelist;
    // 未被使用的空闲链表(未被使用不代表一定可被分配，reserved大页也是空闲大页)
    // 每个NUMA 结点的list_head指向谁？hugetlb大页 首页page结构的lru字段？应该是的
    struct list_head hugepage_freelists[MAX_NUMNODES];

    /* 每个NUMA节点的大页统计 */
    unsigned int nr_huge_pages_node[MAX_NUMNODES]; /* 每个节点的大页总数 */
    unsigned int free_huge_pages_node[MAX_NUMNODES]; /* 每个节点的空闲大页数 */
    unsigned int surplus_huge_pages_node[MAX_NUMNODES]; /* 通过超发机制动态分配的大页数量 */

#ifdef CONFIG_CGROUP_HUGETLB
    /* cgroup相关的控制文件 */
    struct cftype cgroup_files_dfl[7]; /* cgroup v2控制文件 */
    struct cftype cgroup_files_legacy[9]; /* cgroup v1控制文件 */
#endif

    /* 大页类型的名称 */
    char name[HSTATE_NAME_LEN];
};
struct huge_bootmem_page {
    struct list_head list;
    struct hstate *hstate;
};

struct page *alloc_huge_page(struct vm_area_struct *vma, unsigned long addr, int avoid_reserve);
struct page *alloc_huge_page_nodemask(struct hstate *h, int preferred_nid, nodemask_t *nmask, gfp_t gfp_mask);
struct page *alloc_huge_page_vma(struct hstate *h, struct vm_area_struct *vma, unsigned long address);
int huge_add_to_page_cache(struct page *page, struct address_space *mapping, pgoff_t idx);

/* arch callback */
int __init __alloc_bootmem_huge_page(struct hstate *h);
int __init alloc_bootmem_huge_page(struct hstate *h);

void __init hugetlb_add_hstate(unsigned order);
bool __init arch_hugetlb_valid_size(unsigned long size);
struct hstate *size_to_hstate(unsigned long size);

#ifndef HUGE_MAX_HSTATE
#define HUGE_MAX_HSTATE 1
#endif

extern struct hstate hstates[HUGE_MAX_HSTATE];
extern unsigned int default_hstate_idx;

//#define default_hstate (hstates[default_hstate_idx])
struct hstate default_hstate = hstates[default_hstate_idx]; /* 我加的，原始为上一行内容 */
static inline struct hstate *hstate_file(struct file *f)
{
    return hstate_inode(file_inode(f));
}

static inline struct hstate *hstate_sizelog(int page_size_log)
{
    if (!page_size_log)
        return &default_hstate;

    return size_to_hstate(1UL << page_size_log);
}

static inline struct hstate *hstate_vma(struct vm_area_struct *vma)
{
    return hstate_file(vma->vm_file); /* 如果是大页，一定有文件 */
}

static inline unsigned long huge_page_size(struct hstate *h) /* 巨页的大小 */
{
    return (unsigned long)PAGE_SIZE << h->order; /* 大页内存的每一页大小 */
}

extern unsigned long vma_kernel_pagesize(struct vm_area_struct *vma);

extern unsigned long vma_mmu_pagesize(struct vm_area_struct *vma);

static inline unsigned long huge_page_mask(struct hstate *h)
{
    return h->mask;
}

static inline unsigned int huge_page_order(struct hstate *h)
{
    return h->order;
}

static inline unsigned huge_page_shift(struct hstate *h)
{
    return h->order + PAGE_SHIFT;
}

static inline bool hstate_is_gigantic(struct hstate *h)
{
    // 大页大于8MB?
    return huge_page_order(h) >= MAX_ORDER;
}

static inline unsigned int pages_per_huge_page(struct hstate *h)
{
    return 1 << h->order;
}

static inline unsigned int blocks_per_huge_page(struct hstate *h)
{
    return huge_page_size(h) / 512;
}

#include <asm/hugetlb.h>

#ifndef is_hugepage_only_range
static inline int is_hugepage_only_range(struct mm_struct *mm, unsigned long addr, unsigned long len)
{
    return 0;
}
#define is_hugepage_only_range is_hugepage_only_range
#endif

#ifndef arch_clear_hugepage_flags
static inline void arch_clear_hugepage_flags(struct page *page)
{
}
#define arch_clear_hugepage_flags arch_clear_hugepage_flags
#endif

#ifndef arch_make_huge_pte
static inline pte_t arch_make_huge_pte(pte_t entry, struct vm_area_struct *vma, struct page *page, int writable)
{
    return entry;
}
#endif

static inline struct hstate *page_hstate(struct page *page)
{
    VM_BUG_ON_PAGE(!PageHuge(page), page);
    return size_to_hstate(page_size(page));
}

static inline unsigned hstate_index_to_shift(unsigned index)
{
    return hstates[index].order + PAGE_SHIFT;
}

static inline int hstate_index(struct hstate *h)
{
    return h - hstates;
}

pgoff_t __basepage_index(struct page *page);

/* Return page->index in PAGE_SIZE units */
static inline pgoff_t basepage_index(struct page *page)
{
    if (!PageCompound(page))
        return page->index;

    return __basepage_index(page);
}

extern int dissolve_free_huge_page(struct page *page);
extern int dissolve_free_huge_pages(unsigned long start_pfn, unsigned long end_pfn);

#ifdef CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION
#ifndef arch_hugetlb_migration_supported
static inline bool arch_hugetlb_migration_supported(struct hstate *h)
{
    if ((huge_page_shift(h) == PMD_SHIFT) || (huge_page_shift(h) == PUD_SHIFT) || (huge_page_shift(h) == PGDIR_SHIFT))
        return true;
    else
        return false;
}
#endif
#else

#endif

static inline bool hugepage_migration_supported(struct hstate *h)
{
    return arch_hugetlb_migration_supported(h);
}

/*
 * Movability check is different as compared to migration check.
 * It determines whether or not a huge page should be placed on
 * movable zone or not. Movability of any huge page should be
 * required only if huge page size is supported for migration.
 * There wont be any reason for the huge page to be movable if
 * it is not migratable to start with. Also the size of the huge
 * page should be large enough to be placed under a movable zone
 * and still feasible enough to be migratable. Just the presence
 * in movable zone does not make the migration feasible.
 *
 * So even though large huge page sizes like the gigantic ones
 * are migratable they should not be movable because its not
 * feasible to migrate them from movable zone.
 */
static inline bool hugepage_movable_supported(struct hstate *h)
{
    if (!hugepage_migration_supported(h))
        return false;

    if (hstate_is_gigantic(h))
        return false;
    return true;
}

/* Movability of hugepages depends on migration support. */
static inline gfp_t htlb_alloc_mask(struct hstate *h)
{
    if (hugepage_movable_supported(h))
        return GFP_HIGHUSER_MOVABLE;
    else
        return GFP_HIGHUSER;
}

static inline gfp_t htlb_modify_alloc_mask(struct hstate *h, gfp_t gfp_mask)
{
    gfp_t modified_mask = htlb_alloc_mask(h);

    /* Some callers might want to enforce node */
    modified_mask |= (gfp_mask & __GFP_THISNODE);

    modified_mask |= (gfp_mask & __GFP_NOWARN);

    return modified_mask;
}

static inline spinlock_t *huge_pte_lockptr(struct hstate *h, struct mm_struct *mm, pte_t *pte)
{
    if (huge_page_size(h) == PMD_SIZE)
        return pmd_lockptr(mm, (pmd_t *)pte);
    VM_BUG_ON(huge_page_size(h) == PAGE_SIZE);
    return &mm->page_table_lock;
}

#ifndef hugepages_supported
/*
 * Some platform decide whether they support huge pages at boot
 * time. Some of them, such as powerpc, set HPAGE_SHIFT to 0
 * when there is no such support
 */
#define hugepages_supported() (HPAGE_SHIFT != 0)
#endif

void hugetlb_report_usage(struct seq_file *m, struct mm_struct *mm);

static inline void hugetlb_count_add(long l, struct mm_struct *mm)
{
    atomic_long_add(l, &mm->hugetlb_usage);
}

static inline void hugetlb_count_sub(long l, struct mm_struct *mm)
{
    atomic_long_sub(l, &mm->hugetlb_usage);
}

#ifndef set_huge_swap_pte_at
static inline void set_huge_swap_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep, pte_t pte,
                                        unsigned long sz)
{
    set_huge_pte_at(mm, addr, ptep, pte);
}
#endif

#ifndef huge_ptep_modify_prot_start
#define huge_ptep_modify_prot_start huge_ptep_modify_prot_start
static inline pte_t huge_ptep_modify_prot_start(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
    return huge_ptep_get_and_clear(vma->vm_mm, addr, ptep);
}
#endif

#ifndef huge_ptep_modify_prot_commit
#define huge_ptep_modify_prot_commit huge_ptep_modify_prot_commit
static inline void huge_ptep_modify_prot_commit(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep,
                                                pte_t old_pte, pte_t pte)
{
    set_huge_pte_at(vma->vm_mm, addr, ptep, pte);
}
#endif

#else /* CONFIG_HUGETLB_PAGE */

#endif /* CONFIG_HUGETLB_PAGE */

static inline spinlock_t *huge_pte_lock(struct hstate *h, struct mm_struct *mm, pte_t *pte)
{
    spinlock_t *ptl;

    ptl = huge_pte_lockptr(h, mm, pte);
    spin_lock(ptl);
    return ptl;
}

#if defined(CONFIG_HUGETLB_PAGE) && defined(CONFIG_CMA)
extern void __init hugetlb_cma_reserve(int order);
extern void __init hugetlb_cma_check(void);
#else

#endif

#endif /* _LINUX_HUGETLB_H */
