/* SPDX-License-Identifier: GPL-2.0-or-later */
/* internal.h: mm/ internal definitions
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef __MM_INTERNAL_H
#define __MM_INTERNAL_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

/*
 * The set of flags that only affect watermark checking and reclaim
 * behaviour. This is used by the MM to obey the caller constraints
 * about IO, FS and watermark checking while ignoring placement
 * hints such as HIGHMEM usage.
 */
#define GFP_RECLAIM_MASK                                                                                    \
    (__GFP_RECLAIM | __GFP_HIGH | __GFP_IO | __GFP_FS | __GFP_NOWARN | __GFP_RETRY_MAYFAIL | __GFP_NOFAIL | \
     __GFP_NORETRY | __GFP_MEMALLOC | __GFP_NOMEMALLOC | __GFP_ATOMIC)

/* The GFP flags allowed during early boot */
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM | __GFP_IO | __GFP_FS))

/* Control allocation cpuset and node placement constraints */
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL | __GFP_THISNODE)

/* Do not use these with a slab allocator */
#define GFP_SLAB_BUG_MASK (__GFP_DMA32 | __GFP_HIGHMEM | ~__GFP_BITS_MASK)

void page_writeback_init(void);

vm_fault_t do_swap_page(struct vm_fault *vmf);

void free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *start_vma, unsigned long floor,
                   unsigned long ceiling);

static inline bool can_madv_lru_vma(struct vm_area_struct *vma)
{
    return !(vma->vm_flags & (VM_LOCKED | VM_HUGETLB | VM_PFNMAP));
}

void unmap_page_range(struct mmu_gather *tlb, struct vm_area_struct *vma, unsigned long addr, unsigned long end,
                      struct zap_details *details);

void do_page_cache_ra(struct readahead_control *, unsigned long nr_to_read, unsigned long lookahead_size);
void force_page_cache_ra(struct readahead_control *, struct file_ra_state *, unsigned long nr);
static inline void force_page_cache_readahead(struct address_space *mapping, struct file *file, pgoff_t index,
                                              unsigned long nr_to_read)
{
    DEFINE_READAHEAD(ractl, file, mapping, index);
    force_page_cache_ra(&ractl, &file->f_ra, nr_to_read);
}

struct page *find_get_entry(struct address_space *mapping, pgoff_t index);
struct page *find_lock_entry(struct address_space *mapping, pgoff_t index);

/**
 * page_evictable - test whether a page is evictable
 *                  测试页面是否可回收
 *
 * @page: the page to test
 *
 * Test whether page is evictable--i.e., should be placed on active/inactive
 * lists vs unevictable list.
 *
 * Reasons page might not be evictable:
 * (1) page's mapping marked unevictable
 * (2) page is part of an mlocked VMA
 *
 *
 */
static inline bool page_evictable(struct page *page)
{
    bool ret;

    /* Prevent address_space of inode and swap cache from being freed */
    rcu_read_lock();

    ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
    rcu_read_unlock();
    return ret;
}

/*
 * Turn a non-refcounted page (->_refcount == 0) into refcounted with
 * a count of one.
 */
static inline void set_page_refcounted(struct page *page)
{
    VM_BUG_ON_PAGE(PageTail(page), page);
    VM_BUG_ON_PAGE(page_ref_count(page), page);
    set_page_count(page, 1);
}

extern unsigned long highest_memmap_pfn;

/*
 * Maximum number of reclaim retries without progress before the OOM
 * killer is consider the only way forward.
 */
#define MAX_RECLAIM_RETRIES 16

/*
 * in mm/vmscan.c:
 */
extern int isolate_lru_page(struct page *page);
extern void putback_lru_page(struct page *page);

/*
 * in mm/rmap.c:
 */
extern pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address);

/*
 * in mm/page_alloc.c
 */

/*
 * Structure for holding the mostly immutable allocation parameters passed
 * between functions involved in allocations, including the alloc_pages*
 * family of functions.
 *
 * nodemask, migratetype and highest_zoneidx are initialized only once in
 * __alloc_pages_nodemask() and then never change.
 *
 * zonelist, preferred_zone and highest_zoneidx are set first in
 * __alloc_pages_nodemask() for the fast path, and might be later changed
 * in __alloc_pages_slowpath(). All other functions pass the whole structure
 * by a const pointer.
 */
struct alloc_context { /* 分配 page 的信息 */
    /**
     *
     */
    struct zonelist *zonelist; /* zonelist */
    nodemask_t *nodemask; /* node */

    /**
     *
     */
    struct zoneref *preferred_zoneref;
    int migratetype;

    /*
	 * highest_zoneidx represents highest usable zone index of
	 * the allocation request. Due to the nature of the zone,
	 * memory on lower zone than the highest_zoneidx will be
	 * protected by lowmem_reserve[highest_zoneidx].
	 *
	 * highest_zoneidx is also used by reclaim/compaction to limit
	 * the target zone since higher zone than this index cannot be
	 * usable for this allocation request.
	 *
	 * 标识 分配请求 最高 可用的 ZONE idx 。
	 * 低 ZONE 相对于 highest_zoneidx 将被保护，通过 lowmem_reserve[highest_zoneidx]
	 */
    enum zone_type highest_zoneidx;
    bool spread_dirty_pages;
};

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 *
 * Assumption: *_mem_map is contiguous at least up to MAX_ORDER
 */
static inline unsigned long __find_buddy_pfn(unsigned long page_pfn, unsigned int order)
{
    return page_pfn ^ (1 << order); /* 0xffff^0x1 = 0xfffe */
}

extern struct page *__pageblock_pfn_to_page(unsigned long start_pfn, unsigned long end_pfn, struct zone *zone);

/**
 *  返回 这个页块 中第一个物理页面的 page 数据结构
 */
static inline struct page *pageblock_pfn_to_page(unsigned long start_pfn, unsigned long end_pfn, struct zone *zone)
{
    if (zone->contiguous)
        return pfn_to_page(start_pfn);

    return __pageblock_pfn_to_page(start_pfn, end_pfn, zone);
}

extern int __isolate_free_page(struct page *page, unsigned int order);
extern void __putback_isolated_page(struct page *page, unsigned int order, int mt);
extern void memblock_free_pages(struct page *page, unsigned long pfn, unsigned int order);
extern void __free_pages_core(struct page *page, unsigned int order);
extern void prep_compound_page(struct page *page, unsigned int order);
extern void post_alloc_hook(struct page *page, unsigned int order, gfp_t gfp_flags);
extern int user_min_free_kbytes;

extern void zone_pcp_update(struct zone *zone);
extern void zone_pcp_reset(struct zone *zone);

#if defined CONFIG_COMPACTION || defined CONFIG_CMA

/*
 * in mm/compaction.c
 */
/*
 * compact_control is used to track pages being migrated and the free pages
 * they are being migrated to during memory compaction. The free_pfn starts
 * at the end of a zone and migrate_pfn begins at the start. Movable pages
 * are moved to the end of a zone during a compaction run and the run
 * completes when free_pfn <= migrate_pfn
 *
 * 内存规整内部使用的描述符
 */
struct compact_control { /* 内存规整 */
    /**
     *  freepages       空闲页面链表
     *  migratepages    可迁移页面链表
     */
    struct list_head freepages; /* List of free pages to migrate to */
    struct list_head migratepages; /* List of pages being migrated */

    /* 已经分离的空闲页面数量 */
    unsigned int nr_freepages; /* Number of isolated free pages */

    /* 准备迁移的页面数量 */
    unsigned int nr_migratepages; /* Number of pages to migrate */

    /* isolate_freepages() 扫描的起始页帧号 */
    unsigned long free_pfn; /* isolate_freepages search base */

    /* 上一次做内存规整时停止扫描的页帧号 */
    unsigned long migrate_pfn; /* isolate_migratepages search base */
    unsigned long fast_start_pfn; /* a pfn to start linear scan from */

    /* 扫描的 ZONE */
    struct zone *zone;

    /* 已经扫描并用于迁移的页面总数 */
    unsigned long total_migrate_scanned;

    /* 已经扫描并用于空闲页面总数 */
    unsigned long total_free_scanned;
    unsigned short fast_search_fail; /* failures to use free list searches */
    short search_order; /* order to start a fast search at */

    /* 分配掩码 */
    const gfp_t gfp_mask; /* gfp mask of a direct compactor */
    int order; /* order a direct compactor needs */

    /* 迁移类型 */
    int migratetype; /* migratetype of direct compactor */

    /* 页面分配器内部使用的标志位 */
    const unsigned int alloc_flags; /* alloc flags of a direct compactor */

    /* 页面分配器根据分配掩码计算出来的首选zone号 */
    const int highest_zoneidx; /* zone index of a direct compactor */

    /* 页面迁移模式: 同步/异步 */
    enum migrate_mode mode; /* Async or sync migration mode */
    bool ignore_skip_hint; /* Scan blocks even if marked skip */
    bool no_set_skip_hint; /* Don't mark blocks for skipping */
    bool ignore_block_suitable; /* Scan blocks considered unsuitable */
    bool direct_compaction; /* False from kcompactd or /proc/... */
    bool proactive_compaction; /* kcompactd proactive compaction */
    bool whole_zone; /* Whole zone should/has been scanned */
    bool contended; /* Signal lock or sched contention */
    bool rescan; /* Rescanning the same pageblock */
    bool alloc_contig; /* alloc_contig_range allocation */
};

/*
 * Used in direct compaction when a page should be taken from the freelists
 * immediately when one is created during the free path.
 */
struct capture_control { /* 紧致内存机制 */
    struct compact_control *cc;
    struct page *page;
};

unsigned long isolate_freepages_range(struct compact_control *cc, unsigned long start_pfn, unsigned long end_pfn);
unsigned long isolate_migratepages_range(struct compact_control *cc, unsigned long low_pfn, unsigned long end_pfn);
int find_suitable_fallback(struct free_area *area, unsigned int order, int migratetype, bool only_stealable,
                           bool *can_steal);

#endif

/*
 * This function returns the order of a free page in the buddy system. In
 * general, page_zone(page)->lock must be held by the caller to prevent the
 * page from being allocated in parallel and returning garbage as the order.
 * If a caller does not hold page_zone(page)->lock, it must guarantee that the
 * page cannot be allocated or merged in parallel. Alternatively, it must
 * handle invalid values gracefully, and use buddy_order_unsafe() below.
 */
static inline unsigned int buddy_order(struct page *page)
{
    /* PageBuddy() must be checked by the caller */
    return page_private(page);
}

/*
 * Like buddy_order(), but for callers who cannot afford to hold the zone lock.
 * PageBuddy() should be checked first by the caller to minimize race window,
 * and invalid values must be handled gracefully.
 *
 * READ_ONCE is used so that if the caller assigns the result into a local
 * variable and e.g. tests it for valid range before using, the compiler cannot
 * decide to remove the variable and inline the page_private(page) multiple
 * times, potentially observing different values in the tests and the actual
 * use of the result.
 */
#define buddy_order_unsafe(page) READ_ONCE(page_private(page))

static inline bool is_cow_mapping(vm_flags_t flags)
{
    return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

/*
 * These three helpers classifies VMAs for virtual memory accounting.
 */

/*
 * Executable code area - executable, not writable, not stack
 */
static inline bool is_exec_mapping(vm_flags_t flags)
{
    return (flags & (VM_EXEC | VM_WRITE | VM_STACK)) == VM_EXEC;
}

/*
 * Stack area - atomatically grows in one direction
 *
 * VM_GROWSUP / VM_GROWSDOWN VMAs are always private anonymous:
 * do_mmap() forbids all other combinations.
 */
static inline bool is_stack_mapping(vm_flags_t flags)
{
    return (flags & VM_STACK) == VM_STACK;
}

/*
 * Data area - private, writable, not stack
 */
static inline bool is_data_mapping(vm_flags_t flags)
{
    return (flags & (VM_WRITE | VM_SHARED | VM_STACK)) == VM_WRITE;
}

/* mm/util.c */
void __vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma, struct vm_area_struct *prev);
void __vma_unlink_list(struct mm_struct *mm, struct vm_area_struct *vma);

#ifdef CONFIG_MMU
extern long populate_vma_page_range(struct vm_area_struct *vma, unsigned long start, unsigned long end,
                                    int *nonblocking);
extern void munlock_vma_pages_range(struct vm_area_struct *vma, unsigned long start, unsigned long end);
static inline void munlock_vma_pages_all(struct vm_area_struct *vma)
{
    munlock_vma_pages_range(vma, vma->vm_start, vma->vm_end);
}

/*
 * must be called with vma's mmap_lock held for read or write, and page locked.
 */
extern void mlock_vma_page(struct page *page);
extern unsigned int munlock_vma_page(struct page *page);

/*
 * Clear the page's PageMlocked().  This can be useful in a situation where
 * we want to unconditionally remove a page from the pagecache -- e.g.,
 * on truncation or freeing.
 *
 * It is legal to call this function for any page, mlocked or not.
 * If called for a page that is still mapped by mlocked vmas, all we do
 * is revert to lazy LRU behaviour -- semantics are not broken.
 */
extern void clear_page_mlock(struct page *page);

/*
 * mlock_migrate_page - called only from migrate_misplaced_transhuge_page()
 * (because that does not go through the full procedure of migration ptes):
 * to migrate the Mlocked page flag; update statistics.
 */
static inline void mlock_migrate_page(struct page *newpage, struct page *page)
{
    if (TestClearPageMlocked(page)) {
        int nr_pages = thp_nr_pages(page);

        /* Holding pmd lock, no change in irq context: __mod is safe */
        __mod_zone_page_state(page_zone(page), NR_MLOCK, -nr_pages);
        SetPageMlocked(newpage);
        __mod_zone_page_state(page_zone(newpage), NR_MLOCK, nr_pages);
    }
}

extern pmd_t maybe_pmd_mkwrite(pmd_t pmd, struct vm_area_struct *vma);

/*
 * At what user virtual address is page expected in @vma?
 */
static inline unsigned long __vma_address(struct page *page, struct vm_area_struct *vma)
{
    pgoff_t pgoff = page_to_pgoff(page); /* 页内偏移 */

    /* 返回虚拟地址空间的虚拟地址 */
    return vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT /* 12 */);
}

/* 返回 vma 起始虚拟地址 */
static inline unsigned long vma_address(struct page *page, struct vm_area_struct *vma)
{
    unsigned long start, end;

    /* 用户虚拟地址空间的地址 */
    start = __vma_address(page, vma);
    end = start + thp_size(page) - PAGE_SIZE /* 4K */;

    /* page should be within @vma mapping range */
    VM_BUG_ON_VMA(end < vma->vm_start || start >= vma->vm_end, vma);

    return max(start, vma->vm_start);
}

static inline struct file *maybe_unlock_mmap_for_io(struct vm_fault *vmf, struct file *fpin)
{
    int flags = vmf->flags;

    if (fpin)
        return fpin;

    /*
	 * FAULT_FLAG_RETRY_NOWAIT means we don't want to wait on page locks or
	 * anything, so we only pin the file and drop the mmap_lock if only
	 * FAULT_FLAG_ALLOW_RETRY is set, while this is the first attempt.
	 */
    if (fault_flag_allow_retry_first(flags) && !(flags & FAULT_FLAG_RETRY_NOWAIT)) {
        fpin = get_file(vmf->vma->vm_file);
        mmap_read_unlock(vmf->vma->vm_mm);
    }
    return fpin;
}

#else /* !CONFIG_MMU */
//static inline void clear_page_mlock(struct page *page) { }
//static inline void mlock_vma_page(struct page *page) { }
//static inline void mlock_migrate_page(struct page *new, struct page *old) { }

#endif /* !CONFIG_MMU */

/*
 * Return the mem_map entry representing the 'offset' subpage within
 * the maximally aligned gigantic page 'base'.  Handle any discontiguity
 * in the mem_map at MAX_ORDER_NR_PAGES boundaries.
 */
static inline struct page *mem_map_offset(struct page *base, int offset)
{
    if (unlikely(offset >= MAX_ORDER_NR_PAGES))
        return nth_page(base, offset);
    return base + offset;
}

/*
 * Iterator over all subpages within the maximally aligned gigantic
 * page 'base'.  Handle any discontiguity in the mem_map.
 */
static inline struct page *mem_map_next(struct page *iter, struct page *base, int offset)
{
    if (unlikely((offset & (MAX_ORDER_NR_PAGES - 1)) == 0)) {
        unsigned long pfn = page_to_pfn(base) + offset;
        if (!pfn_valid(pfn))
            return NULL;
        return pfn_to_page(pfn);
    }
    return iter + 1;
}

/* Memory initialisation debug and verification */
enum mminit_level { MMINIT_WARNING, MMINIT_VERIFY, MMINIT_TRACE };

#ifdef CONFIG_DEBUG_MEMORY_INIT

extern int mminit_loglevel;

#define mminit_dprintk(level, prefix, fmt, arg...)                   \
    do {                                                             \
        if (level < mminit_loglevel) {                               \
            if (level <= MMINIT_WARNING)                             \
                pr_warn("mminit::" prefix " " fmt, ##arg);           \
            else                                                     \
                printk(KERN_DEBUG "mminit::" prefix " " fmt, ##arg); \
        }                                                            \
    } while (0)

extern void mminit_verify_pageflags_layout(void);
extern void mminit_verify_zonelist(void);
#else

//static inline void mminit_dprintk(enum mminit_level level,
//				const char *prefix, const char *fmt, ...)
//{
//}
//
//static inline void mminit_verify_pageflags_layout(void)
//{
//}
//
//static inline void mminit_verify_zonelist(void)
//{
//}
#endif /* CONFIG_DEBUG_MEMORY_INIT */

/* mminit_validate_memmodel_limits is independent of CONFIG_DEBUG_MEMORY_INIT */
#if defined(CONFIG_SPARSEMEM)
extern void mminit_validate_memmodel_limits(unsigned long *start_pfn, unsigned long *end_pfn);
#else
static inline void mminit_validate_memmodel_limits(unsigned long *start_pfn, unsigned long *end_pfn)
{
}
#endif /* CONFIG_SPARSEMEM */

#define NODE_RECLAIM_NOSCAN -2

#define NODE_RECLAIM_FULL -1

#define NODE_RECLAIM_SOME 0

#define NODE_RECLAIM_SUCCESS 1

#ifdef CONFIG_NUMA
extern int node_reclaim(struct pglist_data *, gfp_t, unsigned int);
#else

#endif

extern int hwpoison_filter(struct page *p);

extern u32 hwpoison_filter_dev_major;
extern u32 hwpoison_filter_dev_minor;
extern u64 hwpoison_filter_flags_mask;
extern u64 hwpoison_filter_flags_value;
extern u64 hwpoison_filter_memcg;
extern u32 hwpoison_filter_enable;

extern unsigned long __must_check vm_mmap_pgoff(struct file *, unsigned long, unsigned long, unsigned long,
                                                unsigned long, unsigned long);

extern void set_pageblock_order(void);
unsigned int reclaim_clean_pages_from_list(struct zone *zone, struct list_head *page_list);

/* The ALLOC_WMARK bits are used as an index to zone->watermark */
#define ALLOC_WMARK_MIN WMARK_MIN /* 最低警戒水位 */
#define ALLOC_WMARK_LOW WMARK_LOW /* 低水位, 唤醒 kswapd */
#define ALLOC_WMARK_HIGH WMARK_HIGH /* 高水位 */
#define ALLOC_NO_WATERMARKS 0x04 /* don't check watermarks at all 可以访问系统给所有内存 */

/* Mask to get the watermark bits */
#define ALLOC_WMARK_MASK (ALLOC_NO_WATERMARKS - 1) /* 0x04-1=0x03 = 0011 */

/*
 * Only MMU archs have async oom victim reclaim - aka oom_reaper so we
 * cannot assume a reduced access to memory reserves is sufficient for
 * !MMU
 */
#ifdef CONFIG_MMU
#define ALLOC_OOM 0x08 /* 用于补偿 OOM 进程或者线程 */
#else

#endif

#define ALLOC_HARDER 0x10 /* try to alloc harder 紧急情况下可以访问预留内存 */
#define ALLOC_HIGH 0x20 /* __GFP_HIGH set 表示进程具有很高的优先级，允许访问预留内存 */
#define ALLOC_CPUSET 0x40 /* check for correct cpuset */
#define ALLOC_CMA 0x80 /* allow allocations from CMA areas */

#ifdef CONFIG_ZONE_DMA32
#define ALLOC_NOFRAGMENT 0x100 /* avoid mixing pageblock types 避免混合页面块类型 */
#else

#endif
/**
 *  唤醒 kswapd
 */
#define ALLOC_KSWAPD 0x800 /* allow waking of kswapd, __GFP_KSWAPD_RECLAIM set */

enum ttu_flags;
struct tlbflush_unmap_batch;

/*
 * only for MM internal work items which do not depend on
 * any allocations or locks which might depend on allocations
 */
extern struct workqueue_struct *mm_percpu_wq;

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
void try_to_unmap_flush(void);
void try_to_unmap_flush_dirty(void);
void flush_tlb_batched_pending(struct mm_struct *mm);
#else

#endif /* CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH */

extern const struct trace_print_flags pageflag_names[];
extern const struct trace_print_flags vmaflag_names[];
extern const struct trace_print_flags gfpflag_names[];

static inline bool is_migrate_highatomic(enum migratetype migratetype)
{
    return migratetype == MIGRATE_HIGHATOMIC;
}

static inline bool is_migrate_highatomic_page(struct page *page)
{
    return get_pageblock_migratetype(page) == MIGRATE_HIGHATOMIC;
}

void setup_zone_pageset(struct zone *zone);

struct migration_target_control {
    int nid; /* 页面迁移的首选目标 NUMA 节点 ID */
    nodemask_t *nmask; /* 可以作为迁移目标的 NUMA 节点掩码 */
    gfp_t gfp_mask; /* 分配标志,决定页面分配行为,eg:
						 ** - GFP_HIGHUSER: 从高端内存区域分配
                         * - __GFP_MOVABLE: 分配可迁移页面
                         * - __GFP_ZERO: 分配时清零
                         * - __GFP_NOWARN: 分配失败时不报警
                         * - __GFP_NORETRY: 分配失败时不重试
                         * - __GFP_NOFAIL: 分配必须成功
                         * - __GFP_ATOMIC: 原子分配,不能睡眠
                         * - __GFP_IO: 允许IO */
};

#endif /* __MM_INTERNAL_H */
