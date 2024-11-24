// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2009  Red Hat, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/mmu_notifier.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/shrinker.h>
#include <linux/mm_inline.h>
#include <linux/swapops.h>
#include <linux/dax.h>
#include <linux/khugepaged.h>
#include <linux/freezer.h>
#include <linux/pfn_t.h>
#include <linux/mman.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/debugfs.h>
#include <linux/migrate.h>
#include <linux/hashtable.h>
#include <linux/userfaultfd_k.h>
#include <linux/page_idle.h>
#include <linux/shmem_fs.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/page_owner.h>

#include <asm/tlb.h>
#include <asm/pgalloc.h>
#include "internal.h"

/*
 * By default, transparent hugepage support is disabled in order to avoid
 * risking an increased memory footprint for applications that are not
 * guaranteed to benefit from it. When transparent hugepage support is
 * enabled, it is for all mappings, and khugepaged scans all mappings.
 * Defrag is invoked by khugepaged hugepage allocations and by page faults
 * for all hugepage allocations.
 *
 * 透明大页设置
 *
 * $ cat /sys/kernel/mm/transparent_hugepage/enabled
 * always [madvise] never
 *
 * 关闭
 * $ grubby --update-kernel=/boot/vmlinuxz-`uname -r` \
 * 		--args="transparent_hugepage=never"
 */
unsigned long __read_mostly transparent_hugepage_flags =
#ifdef CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS /* always */
        (1 << TRANSPARENT_HUGEPAGE_FLAG) |
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE_MADVISE /* madvise */
        (1 << TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG) |
#endif
        (1 << TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG) | (1 << TRANSPARENT_HUGEPAGE_DEFRAG_KHUGEPAGED_FLAG) |
        (1 << TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG);

static struct shrinker deferred_split_shrinker;

static atomic_t huge_zero_refcount;
struct page __read_mostly *huge_zero_page;

bool transparent_hugepage_enabled(struct vm_area_struct *vma)
{
    /* The addr is used to check if the vma size fits */
    unsigned long addr = (vma->vm_end & HPAGE_PMD_MASK) - HPAGE_PMD_SIZE;

    if (!transhuge_vma_suitable(vma, addr))
        return false;
    /**
	 * 匿名页
	 */
    if (vma_is_anonymous(vma))
        return __transparent_hugepage_enabled(vma);
    if (vma_is_shmem(vma))
        return shmem_huge_enabled(vma);

    return false;
}

static struct page *get_huge_zero_page(void)
{
    struct page *zero_page;
retry:
    if (likely(atomic_inc_not_zero(&huge_zero_refcount)))
        return READ_ONCE(huge_zero_page);

    zero_page = alloc_pages((GFP_TRANSHUGE | __GFP_ZERO) & ~__GFP_MOVABLE, HPAGE_PMD_ORDER);
    if (!zero_page) {
        count_vm_event(THP_ZERO_PAGE_ALLOC_FAILED);
        return NULL;
    }
    count_vm_event(THP_ZERO_PAGE_ALLOC);
    preempt_disable();
    if (cmpxchg(&huge_zero_page, NULL, zero_page)) {
        preempt_enable();
        __free_pages(zero_page, compound_order(zero_page));
        goto retry;
    }

    /* We take additional reference here. It will be put back by shrinker */
    atomic_set(&huge_zero_refcount, 2);
    preempt_enable();
    return READ_ONCE(huge_zero_page);
}

static void put_huge_zero_page(void)
{
    /*
	 * Counter should never go to zero here. Only shrinker can put
	 * last reference.
	 */
    BUG_ON(atomic_dec_and_test(&huge_zero_refcount));
}

struct page *mm_get_huge_zero_page(struct mm_struct *mm)
{
    if (test_bit(MMF_HUGE_ZERO_PAGE, &mm->flags))
        return READ_ONCE(huge_zero_page);

    if (!get_huge_zero_page())
        return NULL;

    if (test_and_set_bit(MMF_HUGE_ZERO_PAGE, &mm->flags))
        put_huge_zero_page();

    return READ_ONCE(huge_zero_page);
}

void mm_put_huge_zero_page(struct mm_struct *mm)
{
    if (test_bit(MMF_HUGE_ZERO_PAGE, &mm->flags))
        put_huge_zero_page();
}

static unsigned long shrink_huge_zero_page_count(struct shrinker *shrink, struct shrink_control *sc)
{
    /* we can free zero page only if last reference remains */
    return atomic_read(&huge_zero_refcount) == 1 ? HPAGE_PMD_NR : 0;
}

static unsigned long shrink_huge_zero_page_scan(struct shrinker *shrink, struct shrink_control *sc)
{
    if (atomic_cmpxchg(&huge_zero_refcount, 1, 0) == 1) {
        struct page *zero_page = xchg(&huge_zero_page, NULL);
        BUG_ON(zero_page == NULL);
        __free_pages(zero_page, compound_order(zero_page));
        return HPAGE_PMD_NR;
    }

    return 0;
}

static struct shrinker huge_zero_page_shrinker = {
    .count_objects = shrink_huge_zero_page_count,
    .scan_objects = shrink_huge_zero_page_scan,
    .seeks = DEFAULT_SEEKS,
};

#ifdef CONFIG_SYSFS
static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    if (test_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags))
        return sprintf(buf, "[always] madvise never\n");
    else if (test_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags))
        return sprintf(buf, "always [madvise] never\n");
    else
        return sprintf(buf, "always madvise [never]\n");
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    ssize_t ret = count;

    if (sysfs_streq(buf, "always")) {
        clear_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags);
    } else if (sysfs_streq(buf, "madvise")) {
        clear_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags);
    } else if (sysfs_streq(buf, "never")) {
        clear_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags);
    } else
        ret = -EINVAL;

    if (ret > 0) {
        /**
		 * 开启或关闭 "khugepaged" 进程
		 *
		 * 操作系统后台有一个叫做khugepaged的进程，它会一直扫描所有进程占用的内存，在可能
		 * 的情况下会把4kpage交换为Huge Pages，在这个过程中，对于操作的内存的各种分配活
		 * 动都需要各种内存锁，直接影响程序的内存访问性能，并且，这个过程对于应用是透明的，
		 * 在应用层面不可控制,对于专门为4k page优化的程序来说，可能会造成随机的性能下降现
		 * 象。
		 */
        int err = start_stop_khugepaged();
        if (err)
            ret = err;
    }
    return ret;
}
static struct kobj_attribute enabled_attr = __ATTR(enabled, 0644, enabled_show, enabled_store);

ssize_t single_hugepage_flag_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf,
                                  enum transparent_hugepage_flag flag)
{
    return sprintf(buf, "%d\n", !!test_bit(flag, &transparent_hugepage_flags));
}

ssize_t single_hugepage_flag_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count,
                                   enum transparent_hugepage_flag flag)
{
    unsigned long value;
    int ret;

    ret = kstrtoul(buf, 10, &value);
    if (ret < 0)
        return ret;
    if (value > 1)
        return -EINVAL;

    if (value)
        set_bit(flag, &transparent_hugepage_flags);
    else
        clear_bit(flag, &transparent_hugepage_flags);

    return count;
}

static ssize_t defrag_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags))
        return sprintf(buf, "[always] defer defer+madvise madvise never\n");
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags))
        return sprintf(buf, "always [defer] defer+madvise madvise never\n");
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags))
        return sprintf(buf, "always defer [defer+madvise] madvise never\n");
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags))
        return sprintf(buf, "always defer defer+madvise [madvise] never\n");
    return sprintf(buf, "always defer defer+madvise madvise [never]\n");
}

static ssize_t defrag_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    if (sysfs_streq(buf, "always")) {
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags);
    } else if (sysfs_streq(buf, "defer+madvise")) {
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags);
    } else if (sysfs_streq(buf, "defer")) {
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags);
    } else if (sysfs_streq(buf, "madvise")) {
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags);
    } else if (sysfs_streq(buf, "never")) {
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags);
    } else
        return -EINVAL;

    return count;
}
static struct kobj_attribute defrag_attr = __ATTR(defrag, 0644, defrag_show, defrag_store);

static ssize_t use_zero_page_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return single_hugepage_flag_show(kobj, attr, buf, TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG);
}
static ssize_t use_zero_page_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return single_hugepage_flag_store(kobj, attr, buf, count, TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG);
}
static struct kobj_attribute use_zero_page_attr = __ATTR(use_zero_page, 0644, use_zero_page_show, use_zero_page_store);

static ssize_t hpage_pmd_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%lu\n", HPAGE_PMD_SIZE);
}
static struct kobj_attribute hpage_pmd_size_attr = __ATTR_RO(hpage_pmd_size);

static struct attribute *hugepage_attr[] = {
    &enabled_attr.attr,
    &defrag_attr.attr,
    &use_zero_page_attr.attr,
    &hpage_pmd_size_attr.attr,
#ifdef CONFIG_SHMEM
    &shmem_enabled_attr.attr,
#endif
    NULL,
};

static const struct attribute_group hugepage_attr_group = {
    .attrs = hugepage_attr,
};

static int __init hugepage_init_sysfs(struct kobject **hugepage_kobj)
{
    int err;

    /**
	 * /sys/kernel/mm/transparent_hugepage/
	 */
    *hugepage_kobj = kobject_create_and_add("transparent_hugepage", mm_kobj);
    if (unlikely(!*hugepage_kobj)) {
        pr_err("failed to create transparent hugepage kobject\n");
        return -ENOMEM;
    }

    err = sysfs_create_group(*hugepage_kobj, &hugepage_attr_group);
    if (err) {
        pr_err("failed to register transparent hugepage group\n");
        goto delete_obj;
    }

    err = sysfs_create_group(*hugepage_kobj, &khugepaged_attr_group);
    if (err) {
        pr_err("failed to register transparent hugepage group\n");
        goto remove_hp_group;
    }

    return 0;

remove_hp_group:
    sysfs_remove_group(*hugepage_kobj, &hugepage_attr_group);
delete_obj:
    kobject_put(*hugepage_kobj);
    return err;
}

static void __init hugepage_exit_sysfs(struct kobject *hugepage_kobj)
{
    sysfs_remove_group(hugepage_kobj, &khugepaged_attr_group);
    sysfs_remove_group(hugepage_kobj, &hugepage_attr_group);
    kobject_put(hugepage_kobj);
}
#else

#endif /* CONFIG_SYSFS */

static int __init hugepage_init(void)
{
    int err;
    struct kobject *hugepage_kobj;

    /**
	 * 是否开启了透明大页
	 */
    if (!has_transparent_hugepage()) {
        transparent_hugepage_flags = 0;
        return -EINVAL;
    }

    /*
	 * hugepages can't be allocated by the buddy allocator
	 */
    MAYBE_BUILD_BUG_ON(HPAGE_PMD_ORDER >= MAX_ORDER);
    /*
	 * we use page->mapping and page->index in second tail page
	 * as list_head: assuming THP order >= 2
	 */
    MAYBE_BUILD_BUG_ON(HPAGE_PMD_ORDER < 2);

    err = hugepage_init_sysfs(&hugepage_kobj);
    if (err)
        goto err_sysfs;

    err = khugepaged_init();
    if (err)
        goto err_slab;

    err = register_shrinker(&huge_zero_page_shrinker);
    if (err)
        goto err_hzp_shrinker;
    err = register_shrinker(&deferred_split_shrinker);
    if (err)
        goto err_split_shrinker;

    /*
	 * By default disable transparent hugepages on smaller systems,
	 * where the extra memory used could hurt more than TLB overhead
	 * is likely to save.  The admin can still enable it through /sys.
	 */
    if (totalram_pages() < (512 << (20 - PAGE_SHIFT))) {
        transparent_hugepage_flags = 0;
        return 0;
    }

    /**
	 * 开启或关闭 "khugepaged" 进程
	 *
	 * 操作系统后台有一个叫做khugepaged的进程，它会一直扫描所有进程占用的内存，在可能
	 * 的情况下会把4kpage交换为Huge Pages，在这个过程中，对于操作的内存的各种分配活
	 * 动都需要各种内存锁，直接影响程序的内存访问性能，并且，这个过程对于应用是透明的，
	 * 在应用层面不可控制,对于专门为4k page优化的程序来说，可能会造成随机的性能下降现
	 * 象。
	 */
    err = start_stop_khugepaged();
    if (err)
        goto err_khugepaged;

    return 0;
err_khugepaged:
    unregister_shrinker(&deferred_split_shrinker);
err_split_shrinker:
    unregister_shrinker(&huge_zero_page_shrinker);
err_hzp_shrinker:
    khugepaged_destroy();
err_slab:
    hugepage_exit_sysfs(hugepage_kobj);
err_sysfs:
    return err;
}
subsys_initcall(hugepage_init);

/**
 * 透明大页设置
 *
 * $ cat /sys/kernel/mm/transparent_hugepage/enabled
 * always [madvise] never
 *
 * 关闭
 * $ grubby --update-kernel=/boot/vmlinuxz-`uname -r` \
 * 		--args="transparent_hugepage=never"
 */
static int __init setup_transparent_hugepage(char *str)
{
    int ret = 0;
    if (!str)
        goto out;
    if (!strcmp(str, "always")) {
        set_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags);
        ret = 1;
    } else if (!strcmp(str, "madvise")) {
        clear_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags);
        set_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags);
        ret = 1;
    } else if (!strcmp(str, "never")) {
        clear_bit(TRANSPARENT_HUGEPAGE_FLAG, &transparent_hugepage_flags);
        clear_bit(TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG, &transparent_hugepage_flags);
        ret = 1;
    }
out:
    if (!ret)
        pr_warn("transparent_hugepage= cannot parse, ignored\n");
    return ret;
}
__setup("transparent_hugepage=", setup_transparent_hugepage);

pmd_t maybe_pmd_mkwrite(pmd_t pmd, struct vm_area_struct *vma)
{
    if (likely(vma->vm_flags & VM_WRITE))
        pmd = pmd_mkwrite(pmd);
    return pmd;
}

#ifdef CONFIG_MEMCG
static inline struct deferred_split *get_deferred_split_queue(struct page *page)
{
    struct mem_cgroup *memcg = compound_head(page)->mem_cgroup;
    struct pglist_data *pgdat = NODE_DATA(page_to_nid(page));

    if (memcg)
        return &memcg->deferred_split_queue;
    else
        return &pgdat->deferred_split_queue;
}
#else
static inline struct deferred_split *get_deferred_split_queue(struct page *page)
{
    struct pglist_data *pgdat = NODE_DATA(page_to_nid(page));

    return &pgdat->deferred_split_queue;
}
#endif

void prep_transhuge_page(struct page *page)
{
    /*
	 * we use page->mapping and page->indexlru in second tail page
	 * as list_head: assuming THP order >= 2
	 */

    INIT_LIST_HEAD(page_deferred_list(page));
    set_compound_page_dtor(page, TRANSHUGE_PAGE_DTOR);
}

bool is_transparent_hugepage(struct page *page)
{
    if (!PageCompound(page))
        return false;

    page = compound_head(page);
    return is_huge_zero_page(page) || page[1].compound_dtor == TRANSHUGE_PAGE_DTOR;
}
EXPORT_SYMBOL_GPL(is_transparent_hugepage);

static unsigned long __thp_get_unmapped_area(struct file *filp, unsigned long addr, unsigned long len, loff_t off,
                                             unsigned long flags, unsigned long size)
{
    loff_t off_end = off + len;
    loff_t off_align = round_up(off, size);
    unsigned long len_pad, ret;

    if (off_end <= off_align || (off_end - off_align) < size)
        return 0;

    len_pad = len + size;
    if (len_pad < len || (off + len_pad) < off)
        return 0;
    /**
     *
     */
    ret = current->mm->get_unmapped_area(filp, addr, len_pad, off >> PAGE_SHIFT, flags);

    /*
	 * The failure might be due to length padding. The caller will retry
	 * without the padding.
	 */
    if (IS_ERR_VALUE(ret))
        return 0;

    /*
	 * Do not try to align to THP boundary if allocation at the address
	 * hint succeeds.
	 */
    if (ret == addr)
        return addr;

    ret += (off - ret) & (size - 1);
    return ret;
}

unsigned long thp_get_unmapped_area(struct file *filp, unsigned long addr, unsigned long len, unsigned long pgoff,
                                    unsigned long flags)
{
    unsigned long ret;
    loff_t off = (loff_t)pgoff << PAGE_SHIFT;

    if (!IS_DAX(filp->f_mapping->host) || !IS_ENABLED(CONFIG_FS_DAX_PMD))
        goto out;

    ret = __thp_get_unmapped_area(filp, addr, len, off, flags, PMD_SIZE);
    if (ret)
        return ret;
out:
    return current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
}
EXPORT_SYMBOL_GPL(thp_get_unmapped_area);

static vm_fault_t __do_huge_pmd_anonymous_page(struct vm_fault *vmf, struct page *page, gfp_t gfp)
{
    struct vm_area_struct *vma = vmf->vma;
    pgtable_t pgtable;
    unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
    vm_fault_t ret = 0;

    VM_BUG_ON_PAGE(!PageCompound(page), page);

    if (mem_cgroup_charge(page, vma->vm_mm, gfp)) {
        put_page(page);
        count_vm_event(THP_FAULT_FALLBACK);
        count_vm_event(THP_FAULT_FALLBACK_CHARGE);
        return VM_FAULT_FALLBACK;
    }
    cgroup_throttle_swaprate(page, gfp);

    pgtable = pte_alloc_one(vma->vm_mm);
    if (unlikely(!pgtable)) {
        ret = VM_FAULT_OOM;
        goto release;
    }

    clear_huge_page(page, vmf->address, HPAGE_PMD_NR);
    /*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * clear_huge_page writes become visible before the set_pmd_at()
	 * write.
	 */
    __SetPageUptodate(page);

    vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
    if (unlikely(!pmd_none(*vmf->pmd))) {
        goto unlock_release;
    } else {
        pmd_t entry;

        ret = check_stable_address_space(vma->vm_mm);
        if (ret)
            goto unlock_release;

        /* Deliver the page fault to userland */
        if (userfaultfd_missing(vma)) {
            vm_fault_t ret2;

            spin_unlock(vmf->ptl);
            put_page(page);
            pte_free(vma->vm_mm, pgtable);
            ret2 = handle_userfault(vmf, VM_UFFD_MISSING);
            VM_BUG_ON(ret2 & VM_FAULT_FALLBACK);
            return ret2;
        }

        entry = mk_huge_pmd(page, vma->vm_page_prot);
        entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
        page_add_new_anon_rmap(page, vma, haddr, true);
        lru_cache_add_inactive_or_unevictable(page, vma);
        pgtable_trans_huge_deposit(vma->vm_mm, vmf->pmd, pgtable);
        set_pmd_at(vma->vm_mm, haddr, vmf->pmd, entry);
        add_mm_counter(vma->vm_mm, MM_ANONPAGES, HPAGE_PMD_NR);
        mm_inc_nr_ptes(vma->vm_mm);
        spin_unlock(vmf->ptl);
        count_vm_event(THP_FAULT_ALLOC);
        count_memcg_event_mm(vma->vm_mm, THP_FAULT_ALLOC);
    }

    return 0;
unlock_release:
    spin_unlock(vmf->ptl);
release:
    if (pgtable)
        pte_free(vma->vm_mm, pgtable);
    put_page(page);
    return ret;
}

/*
 * always: directly stall for all thp allocations
 * defer: wake kswapd and fail if not immediately available
 * defer+madvise: wake kswapd and directly stall for MADV_HUGEPAGE, otherwise
 *		  fail if not immediately available
 * madvise: directly stall for MADV_HUGEPAGE, otherwise fail if not immediately
 *	    available
 * never: never stall for any thp allocation
 */
static inline gfp_t alloc_hugepage_direct_gfpmask(struct vm_area_struct *vma)
{
    const bool vma_madvised = !!(vma->vm_flags & VM_HUGEPAGE);

    /* Always do synchronous compaction */
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags))
        return GFP_TRANSHUGE | (vma_madvised ? 0 : __GFP_NORETRY);

    /* Kick kcompactd and fail quickly */
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags))
        return GFP_TRANSHUGE_LIGHT | __GFP_KSWAPD_RECLAIM;

    /* Synchronous compaction if madvised, otherwise kick kcompactd */
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags))
        return GFP_TRANSHUGE_LIGHT | (vma_madvised ? __GFP_DIRECT_RECLAIM : __GFP_KSWAPD_RECLAIM);

    /* Only do synchronous compaction if madvised */
    if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags))
        return GFP_TRANSHUGE_LIGHT | (vma_madvised ? __GFP_DIRECT_RECLAIM : 0);

    return GFP_TRANSHUGE_LIGHT;
}

/* Caller must hold page table lock. */
static bool set_huge_zero_page(pgtable_t pgtable, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long haddr,
                               pmd_t *pmd, struct page *zero_page)
{
    pmd_t entry;
    if (!pmd_none(*pmd))
        return false;
    entry = mk_pmd(zero_page, vma->vm_page_prot);
    entry = pmd_mkhuge(entry);
    if (pgtable)
        pgtable_trans_huge_deposit(mm, pmd, pgtable);
    set_pmd_at(mm, haddr, pmd, entry);
    mm_inc_nr_ptes(mm);
    return true;
}

vm_fault_t do_huge_pmd_anonymous_page(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    gfp_t gfp;
    struct page *page;
    unsigned long haddr = vmf->address & HPAGE_PMD_MASK;

    if (!transhuge_vma_suitable(vma, haddr))
        return VM_FAULT_FALLBACK;
    if (unlikely(anon_vma_prepare(vma)))
        return VM_FAULT_OOM;
    if (unlikely(khugepaged_enter(vma, vma->vm_flags)))
        return VM_FAULT_OOM;
    if (!(vmf->flags & FAULT_FLAG_WRITE) && !mm_forbids_zeropage(vma->vm_mm) && transparent_hugepage_use_zero_page()) {
        pgtable_t pgtable;
        struct page *zero_page;
        vm_fault_t ret;
        pgtable = pte_alloc_one(vma->vm_mm);
        if (unlikely(!pgtable))
            return VM_FAULT_OOM;
        zero_page = mm_get_huge_zero_page(vma->vm_mm);
        if (unlikely(!zero_page)) {
            pte_free(vma->vm_mm, pgtable);
            count_vm_event(THP_FAULT_FALLBACK);
            return VM_FAULT_FALLBACK;
        }
        vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
        ret = 0;
        if (pmd_none(*vmf->pmd)) {
            ret = check_stable_address_space(vma->vm_mm);
            if (ret) {
                spin_unlock(vmf->ptl);
                pte_free(vma->vm_mm, pgtable);
            } else if (userfaultfd_missing(vma)) {
                spin_unlock(vmf->ptl);
                pte_free(vma->vm_mm, pgtable);
                ret = handle_userfault(vmf, VM_UFFD_MISSING);
                VM_BUG_ON(ret & VM_FAULT_FALLBACK);
            } else {
                set_huge_zero_page(pgtable, vma->vm_mm, vma, haddr, vmf->pmd, zero_page);
                spin_unlock(vmf->ptl);
            }
        } else {
            spin_unlock(vmf->ptl);
            pte_free(vma->vm_mm, pgtable);
        }
        return ret;
    }
    gfp = alloc_hugepage_direct_gfpmask(vma);
    page = alloc_hugepage_vma(gfp, vma, haddr, HPAGE_PMD_ORDER);
    if (unlikely(!page)) {
        count_vm_event(THP_FAULT_FALLBACK);
        return VM_FAULT_FALLBACK;
    }
    prep_transhuge_page(page);
    return __do_huge_pmd_anonymous_page(vmf, page, gfp);
}

static void insert_pfn_pmd(struct vm_area_struct *vma, unsigned long addr, pmd_t *pmd, pfn_t pfn, pgprot_t prot,
                           bool write, pgtable_t pgtable)
{
    struct mm_struct *mm = vma->vm_mm;
    pmd_t entry;
    spinlock_t *ptl;

    ptl = pmd_lock(mm, pmd);
    if (!pmd_none(*pmd)) {
        if (write) {
            if (pmd_pfn(*pmd) != pfn_t_to_pfn(pfn)) {
                WARN_ON_ONCE(!is_huge_zero_pmd(*pmd));
                goto out_unlock;
            }
            entry = pmd_mkyoung(*pmd);
            entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
            if (pmdp_set_access_flags(vma, addr, pmd, entry, 1))
                update_mmu_cache_pmd(vma, addr, pmd);
        }

        goto out_unlock;
    }

    entry = pmd_mkhuge(pfn_t_pmd(pfn, prot));
    if (pfn_t_devmap(pfn))
        entry = pmd_mkdevmap(entry);
    if (write) {
        entry = pmd_mkyoung(pmd_mkdirty(entry));
        entry = maybe_pmd_mkwrite(entry, vma);
    }

    if (pgtable) {
        pgtable_trans_huge_deposit(mm, pmd, pgtable);
        mm_inc_nr_ptes(mm);
        pgtable = NULL;
    }

    set_pmd_at(mm, addr, pmd, entry);
    update_mmu_cache_pmd(vma, addr, pmd);

out_unlock:
    spin_unlock(ptl);
    if (pgtable)
        pte_free(mm, pgtable);
}

/**
 * vmf_insert_pfn_pmd_prot - insert a pmd size pfn
 * @vmf: Structure describing the fault
 * @pfn: pfn to insert
 * @pgprot: page protection to use
 * @write: whether it's a write fault
 *
 * Insert a pmd size pfn. See vmf_insert_pfn() for additional info and
 * also consult the vmf_insert_mixed_prot() documentation when
 * @pgprot != @vmf->vma->vm_page_prot.
 *
 * Return: vm_fault_t value.
 */
vm_fault_t vmf_insert_pfn_pmd_prot(struct vm_fault *vmf, pfn_t pfn, pgprot_t pgprot, bool write)
{
    unsigned long addr = vmf->address & PMD_MASK;
    struct vm_area_struct *vma = vmf->vma;
    pgtable_t pgtable = NULL;

    /*
	 * If we had pmd_special, we could avoid all these restrictions,
	 * but we need to be consistent with PTEs and architectures that
	 * can't support a 'special' bit.
	 */
    BUG_ON(!(vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)) && !pfn_t_devmap(pfn));
    BUG_ON((vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)) == (VM_PFNMAP | VM_MIXEDMAP));
    BUG_ON((vma->vm_flags & VM_PFNMAP) && is_cow_mapping(vma->vm_flags));

    if (addr < vma->vm_start || addr >= vma->vm_end)
        return VM_FAULT_SIGBUS;

    if (arch_needs_pgtable_deposit()) {
        pgtable = pte_alloc_one(vma->vm_mm);
        if (!pgtable)
            return VM_FAULT_OOM;
    }

    track_pfn_insert(vma, &pgprot, pfn);

    insert_pfn_pmd(vma, addr, vmf->pmd, pfn, pgprot, write, pgtable);
    return VM_FAULT_NOPAGE;
}
EXPORT_SYMBOL_GPL(vmf_insert_pfn_pmd_prot);

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static pud_t maybe_pud_mkwrite(pud_t pud, struct vm_area_struct *vma)
{
    if (likely(vma->vm_flags & VM_WRITE))
        pud = pud_mkwrite(pud);
    return pud;
}

static void insert_pfn_pud(struct vm_area_struct *vma, unsigned long addr, pud_t *pud, pfn_t pfn, pgprot_t prot,
                           bool write)
{
    struct mm_struct *mm = vma->vm_mm;
    pud_t entry;
    spinlock_t *ptl;

    ptl = pud_lock(mm, pud);
    if (!pud_none(*pud)) {
        if (write) {
            if (pud_pfn(*pud) != pfn_t_to_pfn(pfn)) {
                WARN_ON_ONCE(!is_huge_zero_pud(*pud));
                goto out_unlock;
            }
            entry = pud_mkyoung(*pud);
            entry = maybe_pud_mkwrite(pud_mkdirty(entry), vma);
            if (pudp_set_access_flags(vma, addr, pud, entry, 1))
                update_mmu_cache_pud(vma, addr, pud);
        }
        goto out_unlock;
    }

    entry = pud_mkhuge(pfn_t_pud(pfn, prot));
    if (pfn_t_devmap(pfn))
        entry = pud_mkdevmap(entry);
    if (write) {
        entry = pud_mkyoung(pud_mkdirty(entry));
        entry = maybe_pud_mkwrite(entry, vma);
    }
    set_pud_at(mm, addr, pud, entry);
    update_mmu_cache_pud(vma, addr, pud);

out_unlock:
    spin_unlock(ptl);
}

/**
 * vmf_insert_pfn_pud_prot - insert a pud size pfn
 * @vmf: Structure describing the fault
 * @pfn: pfn to insert
 * @pgprot: page protection to use
 * @write: whether it's a write fault
 *
 * Insert a pud size pfn. See vmf_insert_pfn() for additional info and
 * also consult the vmf_insert_mixed_prot() documentation when
 * @pgprot != @vmf->vma->vm_page_prot.
 *
 * Return: vm_fault_t value.
 */
vm_fault_t vmf_insert_pfn_pud_prot(struct vm_fault *vmf, pfn_t pfn, pgprot_t pgprot, bool write)
{
    unsigned long addr = vmf->address & PUD_MASK;
    struct vm_area_struct *vma = vmf->vma;

    /*
	 * If we had pud_special, we could avoid all these restrictions,
	 * but we need to be consistent with PTEs and architectures that
	 * can't support a 'special' bit.
	 */
    BUG_ON(!(vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)) && !pfn_t_devmap(pfn));
    BUG_ON((vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)) == (VM_PFNMAP | VM_MIXEDMAP));
    BUG_ON((vma->vm_flags & VM_PFNMAP) && is_cow_mapping(vma->vm_flags));

    if (addr < vma->vm_start || addr >= vma->vm_end)
        return VM_FAULT_SIGBUS;

    track_pfn_insert(vma, &pgprot, pfn);

    insert_pfn_pud(vma, addr, vmf->pud, pfn, pgprot, write);
    return VM_FAULT_NOPAGE;
}
EXPORT_SYMBOL_GPL(vmf_insert_pfn_pud_prot);
#endif /* CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */

static void touch_pmd(struct vm_area_struct *vma, unsigned long addr, pmd_t *pmd, int flags)
{
    pmd_t _pmd;

    _pmd = pmd_mkyoung(*pmd);
    if (flags & FOLL_WRITE)
        _pmd = pmd_mkdirty(_pmd);
    if (pmdp_set_access_flags(vma, addr & HPAGE_PMD_MASK, pmd, _pmd, flags & FOLL_WRITE))
        update_mmu_cache_pmd(vma, addr, pmd);
}

struct page *follow_devmap_pmd(struct vm_area_struct *vma, unsigned long addr, pmd_t *pmd, int flags,
                               struct dev_pagemap **pgmap)
{
    unsigned long pfn = pmd_pfn(*pmd);
    struct mm_struct *mm = vma->vm_mm;
    struct page *page;

    assert_spin_locked(pmd_lockptr(mm, pmd));

    /*
	 * When we COW a devmap PMD entry, we split it into PTEs, so we should
	 * not be in this function with `flags & FOLL_COW` set.
	 */
    WARN_ONCE(flags & FOLL_COW, "mm: In follow_devmap_pmd with FOLL_COW set");

    /* FOLL_GET and FOLL_PIN are mutually exclusive. */
    if (WARN_ON_ONCE((flags & (FOLL_PIN | FOLL_GET)) == (FOLL_PIN | FOLL_GET)))
        return NULL;

    if (flags & FOLL_WRITE && !pmd_write(*pmd))
        return NULL;

    if (pmd_present(*pmd) && pmd_devmap(*pmd))
        /* pass */;
    else
        return NULL;

    if (flags & FOLL_TOUCH)
        touch_pmd(vma, addr, pmd, flags);

    /*
	 * device mapped pages can only be returned if the
	 * caller will manage the page reference count.
	 */
    if (!(flags & (FOLL_GET | FOLL_PIN)))
        return ERR_PTR(-EEXIST);

    pfn += (addr & ~PMD_MASK) >> PAGE_SHIFT;
    *pgmap = get_dev_pagemap(pfn, *pgmap);
    if (!*pgmap)
        return ERR_PTR(-EFAULT);
    page = pfn_to_page(pfn);
    if (!try_grab_page(page, flags))
        page = ERR_PTR(-ENOMEM);

    return page;
}

int copy_huge_pmd(struct mm_struct *dst_mm, struct mm_struct *src_mm, pmd_t *dst_pmd, pmd_t *src_pmd,
                  unsigned long addr, struct vm_area_struct *vma)
{
    spinlock_t *dst_ptl, *src_ptl;
    struct page *src_page;
    pmd_t pmd;
    pgtable_t pgtable = NULL;
    int ret = -ENOMEM;

    /* Skip if can be re-fill on fault */
    if (!vma_is_anonymous(vma))
        return 0;

    pgtable = pte_alloc_one(dst_mm);
    if (unlikely(!pgtable))
        goto out;

    dst_ptl = pmd_lock(dst_mm, dst_pmd);
    src_ptl = pmd_lockptr(src_mm, src_pmd);
    spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);

    ret = -EAGAIN;
    pmd = *src_pmd;

    /*
	 * Make sure the _PAGE_UFFD_WP bit is cleared if the new VMA
	 * does not have the VM_UFFD_WP, which means that the uffd
	 * fork event is not enabled.
	 */
    if (!(vma->vm_flags & VM_UFFD_WP))
        pmd = pmd_clear_uffd_wp(pmd);

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
    if (unlikely(is_swap_pmd(pmd))) {
        swp_entry_t entry = pmd_to_swp_entry(pmd);

        VM_BUG_ON(!is_pmd_migration_entry(pmd));
        if (is_write_migration_entry(entry)) {
            make_migration_entry_read(&entry);
            pmd = swp_entry_to_pmd(entry);
            if (pmd_swp_soft_dirty(*src_pmd))
                pmd = pmd_swp_mksoft_dirty(pmd);
            set_pmd_at(src_mm, addr, src_pmd, pmd);
        }
        add_mm_counter(dst_mm, MM_ANONPAGES, HPAGE_PMD_NR);
        mm_inc_nr_ptes(dst_mm);
        pgtable_trans_huge_deposit(dst_mm, dst_pmd, pgtable);
        set_pmd_at(dst_mm, addr, dst_pmd, pmd);
        ret = 0;
        goto out_unlock;
    }
#endif

    if (unlikely(!pmd_trans_huge(pmd))) {
        pte_free(dst_mm, pgtable);
        goto out_unlock;
    }
    /*
	 * When page table lock is held, the huge zero pmd should not be
	 * under splitting since we don't split the page itself, only pmd to
	 * a page table.
	 */
    if (is_huge_zero_pmd(pmd)) {
        struct page *zero_page;
        /*
		 * get_huge_zero_page() will never allocate a new page here,
		 * since we already have a zero page to copy. It just takes a
		 * reference.
		 */
        zero_page = mm_get_huge_zero_page(dst_mm);
        set_huge_zero_page(pgtable, dst_mm, vma, addr, dst_pmd, zero_page);
        ret = 0;
        goto out_unlock;
    }

    src_page = pmd_page(pmd);
    VM_BUG_ON_PAGE(!PageHead(src_page), src_page);

    /*
	 * If this page is a potentially pinned page, split and retry the fault
	 * with smaller page size.  Normally this should not happen because the
	 * userspace should use MADV_DONTFORK upon pinned regions.  This is a
	 * best effort that the pinned pages won't be replaced by another
	 * random page during the coming copy-on-write.
	 */
    if (unlikely(is_cow_mapping(vma->vm_flags) && atomic_read(&src_mm->has_pinned) &&
                 page_maybe_dma_pinned(src_page))) {
        pte_free(dst_mm, pgtable);
        spin_unlock(src_ptl);
        spin_unlock(dst_ptl);
        __split_huge_pmd(vma, src_pmd, addr, false, NULL);
        return -EAGAIN;
    }

    get_page(src_page);
    page_dup_rmap(src_page, true);
    add_mm_counter(dst_mm, MM_ANONPAGES, HPAGE_PMD_NR);
    mm_inc_nr_ptes(dst_mm);
    pgtable_trans_huge_deposit(dst_mm, dst_pmd, pgtable);

    pmdp_set_wrprotect(src_mm, addr, src_pmd);
    pmd = pmd_mkold(pmd_wrprotect(pmd));
    set_pmd_at(dst_mm, addr, dst_pmd, pmd);

    ret = 0;
out_unlock:
    spin_unlock(src_ptl);
    spin_unlock(dst_ptl);
out:
    return ret;
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static void touch_pud(struct vm_area_struct *vma, unsigned long addr, pud_t *pud, int flags)
{
    pud_t _pud;

    _pud = pud_mkyoung(*pud);
    if (flags & FOLL_WRITE)
        _pud = pud_mkdirty(_pud);
    if (pudp_set_access_flags(vma, addr & HPAGE_PUD_MASK, pud, _pud, flags & FOLL_WRITE))
        update_mmu_cache_pud(vma, addr, pud);
}

struct page *follow_devmap_pud(struct vm_area_struct *vma, unsigned long addr, pud_t *pud, int flags,
                               struct dev_pagemap **pgmap)
{
    unsigned long pfn = pud_pfn(*pud);
    struct mm_struct *mm = vma->vm_mm;
    struct page *page;

    assert_spin_locked(pud_lockptr(mm, pud));

    if (flags & FOLL_WRITE && !pud_write(*pud))
        return NULL;

    /* FOLL_GET and FOLL_PIN are mutually exclusive. */
    if (WARN_ON_ONCE((flags & (FOLL_PIN | FOLL_GET)) == (FOLL_PIN | FOLL_GET)))
        return NULL;

    if (pud_present(*pud) && pud_devmap(*pud))
        /* pass */;
    else
        return NULL;

    if (flags & FOLL_TOUCH)
        touch_pud(vma, addr, pud, flags);

    /*
	 * device mapped pages can only be returned if the
	 * caller will manage the page reference count.
	 *
	 * At least one of FOLL_GET | FOLL_PIN must be set, so assert that here:
	 */
    if (!(flags & (FOLL_GET | FOLL_PIN)))
        return ERR_PTR(-EEXIST);

    pfn += (addr & ~PUD_MASK) >> PAGE_SHIFT;
    *pgmap = get_dev_pagemap(pfn, *pgmap);
    if (!*pgmap)
        return ERR_PTR(-EFAULT);
    page = pfn_to_page(pfn);
    if (!try_grab_page(page, flags))
        page = ERR_PTR(-ENOMEM);

    return page;
}

int copy_huge_pud(struct mm_struct *dst_mm, struct mm_struct *src_mm, pud_t *dst_pud, pud_t *src_pud,
                  unsigned long addr, struct vm_area_struct *vma)
{
    spinlock_t *dst_ptl, *src_ptl;
    pud_t pud;
    int ret;

    dst_ptl = pud_lock(dst_mm, dst_pud);
    src_ptl = pud_lockptr(src_mm, src_pud);
    spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);

    ret = -EAGAIN;
    pud = *src_pud;
    if (unlikely(!pud_trans_huge(pud) && !pud_devmap(pud)))
        goto out_unlock;

    /*
	 * When page table lock is held, the huge zero pud should not be
	 * under splitting since we don't split the page itself, only pud to
	 * a page table.
	 */
    if (is_huge_zero_pud(pud)) {
        /* No huge zero pud yet */
    }

    /* Please refer to comments in copy_huge_pmd() */
    if (unlikely(is_cow_mapping(vma->vm_flags) && atomic_read(&src_mm->has_pinned) &&
                 page_maybe_dma_pinned(pud_page(pud)))) {
        spin_unlock(src_ptl);
        spin_unlock(dst_ptl);
        __split_huge_pud(vma, src_pud, addr);
        return -EAGAIN;
    }

    pudp_set_wrprotect(src_mm, addr, src_pud);
    pud = pud_mkold(pud_wrprotect(pud));
    set_pud_at(dst_mm, addr, dst_pud, pud);

    ret = 0;
out_unlock:
    spin_unlock(src_ptl);
    spin_unlock(dst_ptl);
    return ret;
}

void huge_pud_set_accessed(struct vm_fault *vmf, pud_t orig_pud)
{
    pud_t entry;
    unsigned long haddr;
    bool write = vmf->flags & FAULT_FLAG_WRITE;

    vmf->ptl = pud_lock(vmf->vma->vm_mm, vmf->pud);
    if (unlikely(!pud_same(*vmf->pud, orig_pud)))
        goto unlock;

    entry = pud_mkyoung(orig_pud);
    if (write)
        entry = pud_mkdirty(entry);
    haddr = vmf->address & HPAGE_PUD_MASK;
    if (pudp_set_access_flags(vmf->vma, haddr, vmf->pud, entry, write))
        update_mmu_cache_pud(vmf->vma, vmf->address, vmf->pud);

unlock:
    spin_unlock(vmf->ptl);
}
#endif /* CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */

void huge_pmd_set_accessed(struct vm_fault *vmf, pmd_t orig_pmd)
{
    pmd_t entry;
    unsigned long haddr;
    bool write = vmf->flags & FAULT_FLAG_WRITE;

    vmf->ptl = pmd_lock(vmf->vma->vm_mm, vmf->pmd);
    if (unlikely(!pmd_same(*vmf->pmd, orig_pmd)))
        goto unlock;

    entry = pmd_mkyoung(orig_pmd);
    if (write)
        entry = pmd_mkdirty(entry);
    haddr = vmf->address & HPAGE_PMD_MASK;
    if (pmdp_set_access_flags(vmf->vma, haddr, vmf->pmd, entry, write))
        update_mmu_cache_pmd(vmf->vma, vmf->address, vmf->pmd);

unlock:
    spin_unlock(vmf->ptl);
}

vm_fault_t do_huge_pmd_wp_page(struct vm_fault *vmf, pmd_t orig_pmd)
{
    struct vm_area_struct *vma = vmf->vma;
    struct page *page;
    unsigned long haddr = vmf->address & HPAGE_PMD_MASK;

    vmf->ptl = pmd_lockptr(vma->vm_mm, vmf->pmd);
    VM_BUG_ON_VMA(!vma->anon_vma, vma);

    if (is_huge_zero_pmd(orig_pmd))
        goto fallback;

    spin_lock(vmf->ptl);

    if (unlikely(!pmd_same(*vmf->pmd, orig_pmd))) {
        spin_unlock(vmf->ptl);
        return 0;
    }

    page = pmd_page(orig_pmd);
    VM_BUG_ON_PAGE(!PageCompound(page) || !PageHead(page), page);

    /* Lock page for reuse_swap_page() */
    if (!trylock_page(page)) {
        get_page(page);
        spin_unlock(vmf->ptl);
        lock_page(page);
        spin_lock(vmf->ptl);
        if (unlikely(!pmd_same(*vmf->pmd, orig_pmd))) {
            spin_unlock(vmf->ptl);
            unlock_page(page);
            put_page(page);
            return 0;
        }
        put_page(page);
    }

    /*
	 * We can only reuse the page if nobody else maps the huge page or it's
	 * part.
	 */
    if (reuse_swap_page(page, NULL)) {
        pmd_t entry;
        entry = pmd_mkyoung(orig_pmd);
        entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
        if (pmdp_set_access_flags(vma, haddr, vmf->pmd, entry, 1))
            update_mmu_cache_pmd(vma, vmf->address, vmf->pmd);
        unlock_page(page);
        spin_unlock(vmf->ptl);
        return VM_FAULT_WRITE;
    }

    unlock_page(page);
    spin_unlock(vmf->ptl);
fallback:
    __split_huge_pmd(vma, vmf->pmd, vmf->address, false, NULL);
    return VM_FAULT_FALLBACK;
}

/*
 * FOLL_FORCE can write to even unwritable pmd's, but only
 * after we've gone through a COW cycle and they are dirty.
 */
static inline bool can_follow_write_pmd(pmd_t pmd, unsigned int flags)
{
    return pmd_write(pmd) || ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pmd_dirty(pmd));
}

struct page *follow_trans_huge_pmd(struct vm_area_struct *vma, unsigned long addr, pmd_t *pmd, unsigned int flags)
{
    struct mm_struct *mm = vma->vm_mm;
    struct page *page = NULL;

    assert_spin_locked(pmd_lockptr(mm, pmd));

    if (flags & FOLL_WRITE && !can_follow_write_pmd(*pmd, flags))
        goto out;

    /* Avoid dumping huge zero page */
    if ((flags & FOLL_DUMP) && is_huge_zero_pmd(*pmd))
        return ERR_PTR(-EFAULT);

    /* Full NUMA hinting faults to serialise migration in fault paths */
    if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
        goto out;

    page = pmd_page(*pmd);
    VM_BUG_ON_PAGE(!PageHead(page) && !is_zone_device_page(page), page);

    if (!try_grab_page(page, flags))
        return ERR_PTR(-ENOMEM);

    if (flags & FOLL_TOUCH)
        touch_pmd(vma, addr, pmd, flags);

    if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
        /*
		 * We don't mlock() pte-mapped THPs. This way we can avoid
		 * leaking mlocked pages into non-VM_LOCKED VMAs.
		 *
		 * For anon THP:
		 *
		 * In most cases the pmd is the only mapping of the page as we
		 * break COW for the mlock() -- see gup_flags |= FOLL_WRITE for
		 * writable private mappings in populate_vma_page_range().
		 *
		 * The only scenario when we have the page shared here is if we
		 * mlocking read-only mapping shared over fork(). We skip
		 * mlocking such pages.
		 *
		 * For file THP:
		 *
		 * We can expect PageDoubleMap() to be stable under page lock:
		 * for file pages we set it in page_add_file_rmap(), which
		 * requires page to be locked.
		 */

        if (PageAnon(page) && compound_mapcount(page) != 1)
            goto skip_mlock;
        if (PageDoubleMap(page) || !page->mapping)
            goto skip_mlock;
        if (!trylock_page(page))
            goto skip_mlock;
        if (page->mapping && !PageDoubleMap(page))
            mlock_vma_page(page);
        unlock_page(page);
    }
skip_mlock:
    page += (addr & ~HPAGE_PMD_MASK) >> PAGE_SHIFT;
    VM_BUG_ON_PAGE(!PageCompound(page) && !is_zone_device_page(page), page);

out:
    return page;
}

/* NUMA hinting page fault entry point for trans huge pmds */
vm_fault_t do_huge_pmd_numa_page(struct vm_fault *vmf, pmd_t pmd)
{
    struct vm_area_struct *vma = vmf->vma;
    struct anon_vma *anon_vma = NULL;
    struct page *page;
    unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
    int page_nid = NUMA_NO_NODE, this_nid = numa_node_id();
    int target_nid, last_cpupid = -1;
    bool page_locked;
    bool migrated = false;
    bool was_writable;
    int flags = 0;

    vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);
    if (unlikely(!pmd_same(pmd, *vmf->pmd)))
        goto out_unlock;

    /*
	 * If there are potential migrations, wait for completion and retry
	 * without disrupting NUMA hinting information. Do not relock and
	 * check_same as the page may no longer be mapped.
	 */
    if (unlikely(pmd_trans_migrating(*vmf->pmd))) {
        page = pmd_page(*vmf->pmd);
        if (!get_page_unless_zero(page))
            goto out_unlock;
        spin_unlock(vmf->ptl);
        put_and_wait_on_page_locked(page);
        goto out;
    }

    page = pmd_page(pmd);
    BUG_ON(is_huge_zero_page(page));
    page_nid = page_to_nid(page);
    last_cpupid = page_cpupid_last(page);
    count_vm_numa_event(NUMA_HINT_FAULTS);
    if (page_nid == this_nid) {
        count_vm_numa_event(NUMA_HINT_FAULTS_LOCAL);
        flags |= TNF_FAULT_LOCAL;
    }

    /* See similar comment in do_numa_page for explanation */
    if (!pmd_savedwrite(pmd))
        flags |= TNF_NO_GROUP;

    /*
	 * Acquire the page lock to serialise THP migrations but avoid dropping
	 * page_table_lock if at all possible
	 */
    page_locked = trylock_page(page);
    target_nid = mpol_misplaced(page, vma, haddr);
    if (target_nid == NUMA_NO_NODE) {
        /* If the page was locked, there are no parallel migrations */
        if (page_locked)
            goto clear_pmdnuma;
    }

    /* Migration could have started since the pmd_trans_migrating check */
    if (!page_locked) {
        page_nid = NUMA_NO_NODE;
        if (!get_page_unless_zero(page))
            goto out_unlock;
        spin_unlock(vmf->ptl);
        put_and_wait_on_page_locked(page);
        goto out;
    }

    /*
	 * Page is misplaced. Page lock serialises migrations. Acquire anon_vma
	 * to serialises splits
	 */
    get_page(page);
    spin_unlock(vmf->ptl);
    anon_vma = page_lock_anon_vma_read(page);

    /* Confirm the PMD did not change while page_table_lock was released */
    spin_lock(vmf->ptl);
    if (unlikely(!pmd_same(pmd, *vmf->pmd))) {
        unlock_page(page);
        put_page(page);
        page_nid = NUMA_NO_NODE;
        goto out_unlock;
    }

    /* Bail if we fail to protect against THP splits for any reason */
    if (unlikely(!anon_vma)) {
        put_page(page);
        page_nid = NUMA_NO_NODE;
        goto clear_pmdnuma;
    }

    /*
	 * Since we took the NUMA fault, we must have observed the !accessible
	 * bit. Make sure all other CPUs agree with that, to avoid them
	 * modifying the page we're about to migrate.
	 *
	 * Must be done under PTL such that we'll observe the relevant
	 * inc_tlb_flush_pending().
	 *
	 * We are not sure a pending tlb flush here is for a huge page
	 * mapping or not. Hence use the tlb range variant
	 */
    if (mm_tlb_flush_pending(vma->vm_mm)) {
        flush_tlb_range(vma, haddr, haddr + HPAGE_PMD_SIZE);
        /*
		 * change_huge_pmd() released the pmd lock before
		 * invalidating the secondary MMUs sharing the primary
		 * MMU pagetables (with ->invalidate_range()). The
		 * mmu_notifier_invalidate_range_end() (which
		 * internally calls ->invalidate_range()) in
		 * change_pmd_range() will run after us, so we can't
		 * rely on it here and we need an explicit invalidate.
		 */
        mmu_notifier_invalidate_range(vma->vm_mm, haddr, haddr + HPAGE_PMD_SIZE);
    }

    /*
	 * Migrate the THP to the requested node, returns with page unlocked
	 * and access rights restored.
	 */
    spin_unlock(vmf->ptl);

    migrated = migrate_misplaced_transhuge_page(vma->vm_mm, vma, vmf->pmd, pmd, vmf->address, page, target_nid);
    if (migrated) {
        flags |= TNF_MIGRATED;
        page_nid = target_nid;
    } else
        flags |= TNF_MIGRATE_FAIL;

    goto out;
clear_pmdnuma:
    BUG_ON(!PageLocked(page));
    was_writable = pmd_savedwrite(pmd);
    pmd = pmd_modify(pmd, vma->vm_page_prot);
    pmd = pmd_mkyoung(pmd);
    if (was_writable)
        pmd = pmd_mkwrite(pmd);
    set_pmd_at(vma->vm_mm, haddr, vmf->pmd, pmd);
    update_mmu_cache_pmd(vma, vmf->address, vmf->pmd);
    unlock_page(page);
out_unlock:
    spin_unlock(vmf->ptl);

out:
    if (anon_vma)
        page_unlock_anon_vma_read(anon_vma);

    /**
	 * numa balance功能的基本实现过程:
	 * -----------------------------------
	 * 1. 周期性扫描task的地址空间并且修改页表项为PAGE_NONE(没有读/写/执行权限，但是
	 *    有对应的物理地址),之后访问该数据时会发生page fault。
	 * 2. 在page fault中，重新修改页表为正确的权限使得后面能够继续执行
	 * 3. 在page fault中会追踪两个数据: page被哪个节点和任务访问过，任务在各个节点上
	 *    发生的缺页情况
	 * 4. 根据历史记录，决定是否迁移页和任务迁移
	 * ref: https://blog.csdn.net/faxiang1230/article/details/123709414
	 */
    if (page_nid != NUMA_NO_NODE)
        task_numa_fault(last_cpupid, page_nid, HPAGE_PMD_NR, flags);

    return 0;
}

/*
 * Return true if we do MADV_FREE successfully on entire pmd page.
 * Otherwise, return false.
 */
bool madvise_free_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma, pmd_t *pmd, unsigned long addr,
                           unsigned long next)
{
    spinlock_t *ptl;
    pmd_t orig_pmd;
    struct page *page;
    struct mm_struct *mm = tlb->mm;
    bool ret = false;

    tlb_change_page_size(tlb, HPAGE_PMD_SIZE);

    ptl = pmd_trans_huge_lock(pmd, vma);
    if (!ptl)
        goto out_unlocked;

    orig_pmd = *pmd;
    if (is_huge_zero_pmd(orig_pmd))
        goto out;

    if (unlikely(!pmd_present(orig_pmd))) {
        VM_BUG_ON(thp_migration_supported() && !is_pmd_migration_entry(orig_pmd));
        goto out;
    }

    page = pmd_page(orig_pmd);
    /*
	 * If other processes are mapping this page, we couldn't discard
	 * the page unless they all do MADV_FREE so let's skip the page.
	 */
    if (page_mapcount(page) != 1)
        goto out;

    if (!trylock_page(page))
        goto out;

    /*
	 * If user want to discard part-pages of THP, split it so MADV_FREE
	 * will deactivate only them.
	 */
    if (next - addr != HPAGE_PMD_SIZE) {
        get_page(page);
        spin_unlock(ptl);
        split_huge_page(page);
        unlock_page(page);
        put_page(page);
        goto out_unlocked;
    }

    if (PageDirty(page))
        ClearPageDirty(page);
    unlock_page(page);

    if (pmd_young(orig_pmd) || pmd_dirty(orig_pmd)) {
        pmdp_invalidate(vma, addr, pmd);
        orig_pmd = pmd_mkold(orig_pmd);
        orig_pmd = pmd_mkclean(orig_pmd);

        set_pmd_at(mm, addr, pmd, orig_pmd);
        tlb_remove_pmd_tlb_entry(tlb, pmd, addr);
    }

    mark_page_lazyfree(page);
    ret = true;
out:
    spin_unlock(ptl);
out_unlocked:
    return ret;
}

static inline void zap_deposited_table(struct mm_struct *mm, pmd_t *pmd)
{
    pgtable_t pgtable;

    pgtable = pgtable_trans_huge_withdraw(mm, pmd);
    pte_free(mm, pgtable);
    mm_dec_nr_ptes(mm);
}

int zap_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma, pmd_t *pmd, unsigned long addr)
{
    pmd_t orig_pmd;
    spinlock_t *ptl;

    tlb_change_page_size(tlb, HPAGE_PMD_SIZE);

    ptl = __pmd_trans_huge_lock(pmd, vma);
    if (!ptl)
        return 0;
    /*
	 * For architectures like ppc64 we look at deposited pgtable
	 * when calling pmdp_huge_get_and_clear. So do the
	 * pgtable_trans_huge_withdraw after finishing pmdp related
	 * operations.
	 */
    orig_pmd = pmdp_huge_get_and_clear_full(vma, addr, pmd, tlb->fullmm);
    tlb_remove_pmd_tlb_entry(tlb, pmd, addr);
    if (vma_is_special_huge(vma)) {
        if (arch_needs_pgtable_deposit())
            zap_deposited_table(tlb->mm, pmd);
        spin_unlock(ptl);
        if (is_huge_zero_pmd(orig_pmd))
            tlb_remove_page_size(tlb, pmd_page(orig_pmd), HPAGE_PMD_SIZE);
    } else if (is_huge_zero_pmd(orig_pmd)) {
        zap_deposited_table(tlb->mm, pmd);
        spin_unlock(ptl);
        tlb_remove_page_size(tlb, pmd_page(orig_pmd), HPAGE_PMD_SIZE);
    } else {
        struct page *page = NULL;
        int flush_needed = 1;

        if (pmd_present(orig_pmd)) {
            page = pmd_page(orig_pmd);
            page_remove_rmap(page, true);
            VM_BUG_ON_PAGE(page_mapcount(page) < 0, page);
            VM_BUG_ON_PAGE(!PageHead(page), page);
        } else if (thp_migration_supported()) {
            swp_entry_t entry;

            VM_BUG_ON(!is_pmd_migration_entry(orig_pmd));
            entry = pmd_to_swp_entry(orig_pmd);
            page = pfn_to_page(swp_offset(entry));
            flush_needed = 0;
        } else
            WARN_ONCE(1, "Non present huge pmd without pmd migration enabled!");

        if (PageAnon(page)) {
            zap_deposited_table(tlb->mm, pmd);
            add_mm_counter(tlb->mm, MM_ANONPAGES, -HPAGE_PMD_NR);
        } else {
            if (arch_needs_pgtable_deposit())
                zap_deposited_table(tlb->mm, pmd);
            add_mm_counter(tlb->mm, mm_counter_file(page), -HPAGE_PMD_NR);
        }

        spin_unlock(ptl);
        if (flush_needed)
            tlb_remove_page_size(tlb, page, HPAGE_PMD_SIZE);
    }
    return 1;
}

#ifndef pmd_move_must_withdraw
static inline int pmd_move_must_withdraw(spinlock_t *new_pmd_ptl, spinlock_t *old_pmd_ptl, struct vm_area_struct *vma)
{
    /*
	 * With split pmd lock we also need to move preallocated
	 * PTE page table if new_pmd is on different PMD page table.
	 *
	 * We also don't deposit and withdraw tables for file pages.
	 */
    return (new_pmd_ptl != old_pmd_ptl) && vma_is_anonymous(vma);
}
#endif

static pmd_t move_soft_dirty_pmd(pmd_t pmd)
{
#ifdef CONFIG_MEM_SOFT_DIRTY
    if (unlikely(is_pmd_migration_entry(pmd)))
        pmd = pmd_swp_mksoft_dirty(pmd);
    else if (pmd_present(pmd))
        pmd = pmd_mksoft_dirty(pmd);
#endif
    return pmd;
}

bool move_huge_pmd(struct vm_area_struct *vma, unsigned long old_addr, unsigned long new_addr, pmd_t *old_pmd,
                   pmd_t *new_pmd)
{
    spinlock_t *old_ptl, *new_ptl;
    pmd_t pmd;
    struct mm_struct *mm = vma->vm_mm;
    bool force_flush = false;

    /*
	 * The destination pmd shouldn't be established, free_pgtables()
	 * should have release it.
	 */
    if (WARN_ON(!pmd_none(*new_pmd))) {
        VM_BUG_ON(pmd_trans_huge(*new_pmd));
        return false;
    }

    /*
	 * We don't have to worry about the ordering of src and dst
	 * ptlocks because exclusive mmap_lock prevents deadlock.
	 */
    old_ptl = __pmd_trans_huge_lock(old_pmd, vma);
    if (old_ptl) {
        new_ptl = pmd_lockptr(mm, new_pmd);
        if (new_ptl != old_ptl)
            spin_lock_nested(new_ptl, SINGLE_DEPTH_NESTING);
        pmd = pmdp_huge_get_and_clear(mm, old_addr, old_pmd);
        if (pmd_present(pmd))
            force_flush = true;
        VM_BUG_ON(!pmd_none(*new_pmd));

        if (pmd_move_must_withdraw(new_ptl, old_ptl, vma)) {
            pgtable_t pgtable;
            pgtable = pgtable_trans_huge_withdraw(mm, old_pmd);
            pgtable_trans_huge_deposit(mm, new_pmd, pgtable);
        }
        pmd = move_soft_dirty_pmd(pmd);
        set_pmd_at(mm, new_addr, new_pmd, pmd);
        if (force_flush)
            flush_tlb_range(vma, old_addr, old_addr + PMD_SIZE);
        if (new_ptl != old_ptl)
            spin_unlock(new_ptl);
        spin_unlock(old_ptl);
        return true;
    }
    return false;
}

/*
 * Returns
 *  - 0 if PMD could not be locked
 *  - 1 if PMD was locked but protections unchange and TLB flush unnecessary
 *  - HPAGE_PMD_NR is protections changed and TLB flush necessary
 */
int change_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd, unsigned long addr, pgprot_t newprot,
                    unsigned long cp_flags)
{
    struct mm_struct *mm = vma->vm_mm;
    spinlock_t *ptl;
    pmd_t entry;
    bool preserve_write;
    int ret;
    bool prot_numa = cp_flags & MM_CP_PROT_NUMA;
    bool uffd_wp = cp_flags & MM_CP_UFFD_WP;
    bool uffd_wp_resolve = cp_flags & MM_CP_UFFD_WP_RESOLVE;

    ptl = __pmd_trans_huge_lock(pmd, vma);
    if (!ptl)
        return 0;

    preserve_write = prot_numa && pmd_write(*pmd);
    ret = 1;

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
    if (is_swap_pmd(*pmd)) {
        swp_entry_t entry = pmd_to_swp_entry(*pmd);

        VM_BUG_ON(!is_pmd_migration_entry(*pmd));
        if (is_write_migration_entry(entry)) {
            pmd_t newpmd;
            /*
			 * A protection check is difficult so
			 * just be safe and disable write
			 */
            make_migration_entry_read(&entry);
            newpmd = swp_entry_to_pmd(entry);
            if (pmd_swp_soft_dirty(*pmd))
                newpmd = pmd_swp_mksoft_dirty(newpmd);
            set_pmd_at(mm, addr, pmd, newpmd);
        }
        goto unlock;
    }
#endif

    /*
	 * Avoid trapping faults against the zero page. The read-only
	 * data is likely to be read-cached on the local CPU and
	 * local/remote hits to the zero page are not interesting.
	 */
    if (prot_numa && is_huge_zero_pmd(*pmd))
        goto unlock;

    if (prot_numa && pmd_protnone(*pmd))
        goto unlock;

    /*
	 * In case prot_numa, we are under mmap_read_lock(mm). It's critical
	 * to not clear pmd intermittently to avoid race with MADV_DONTNEED
	 * which is also under mmap_read_lock(mm):
	 *
	 *	CPU0:				CPU1:
	 *				change_huge_pmd(prot_numa=1)
	 *				 pmdp_huge_get_and_clear_notify()
	 * madvise_dontneed()
	 *  zap_pmd_range()
	 *   pmd_trans_huge(*pmd) == 0 (without ptl)
	 *   // skip the pmd
	 *				 set_pmd_at();
	 *				 // pmd is re-established
	 *
	 * The race makes MADV_DONTNEED miss the huge pmd and don't clear it
	 * which may break userspace.
	 *
	 * pmdp_invalidate() is required to make sure we don't miss
	 * dirty/young flags set by hardware.
	 */
    entry = pmdp_invalidate(vma, addr, pmd);

    entry = pmd_modify(entry, newprot);
    if (preserve_write)
        entry = pmd_mk_savedwrite(entry);
    if (uffd_wp) {
        entry = pmd_wrprotect(entry);
        entry = pmd_mkuffd_wp(entry);
    } else if (uffd_wp_resolve) {
        /*
		 * Leave the write bit to be handled by PF interrupt
		 * handler, then things like COW could be properly
		 * handled.
		 */
        entry = pmd_clear_uffd_wp(entry);
    }
    ret = HPAGE_PMD_NR;
    set_pmd_at(mm, addr, pmd, entry);
    BUG_ON(vma_is_anonymous(vma) && !preserve_write && pmd_write(entry));
unlock:
    spin_unlock(ptl);
    return ret;
}

/*
 * Returns page table lock pointer if a given pmd maps a thp, NULL otherwise.
 *
 * Note that if it returns page table lock pointer, this routine returns without
 * unlocking page table lock. So callers must unlock it.
 */
spinlock_t *__pmd_trans_huge_lock(pmd_t *pmd, struct vm_area_struct *vma)
{
    spinlock_t *ptl;
    ptl = pmd_lock(vma->vm_mm, pmd);
    if (likely(is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)))
        return ptl;
    spin_unlock(ptl);
    return NULL;
}

/*
 * Returns true if a given pud maps a thp, false otherwise.
 *
 * Note that if it returns true, this routine returns without unlocking page
 * table lock. So callers must unlock it.
 */
spinlock_t *__pud_trans_huge_lock(pud_t *pud, struct vm_area_struct *vma)
{
    spinlock_t *ptl;

    ptl = pud_lock(vma->vm_mm, pud);
    if (likely(pud_trans_huge(*pud) || pud_devmap(*pud)))
        return ptl;
    spin_unlock(ptl);
    return NULL;
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
int zap_huge_pud(struct mmu_gather *tlb, struct vm_area_struct *vma, pud_t *pud, unsigned long addr)
{
    spinlock_t *ptl;

    ptl = __pud_trans_huge_lock(pud, vma);
    if (!ptl)
        return 0;
    /*
	 * For architectures like ppc64 we look at deposited pgtable
	 * when calling pudp_huge_get_and_clear. So do the
	 * pgtable_trans_huge_withdraw after finishing pudp related
	 * operations.
	 */
    pudp_huge_get_and_clear_full(tlb->mm, addr, pud, tlb->fullmm);
    tlb_remove_pud_tlb_entry(tlb, pud, addr);
    if (vma_is_special_huge(vma)) {
        spin_unlock(ptl);
        /* No zero page support yet */
    } else {
        /* No support for anonymous PUD pages yet */
        BUG();
    }
    return 1;
}

static void __split_huge_pud_locked(struct vm_area_struct *vma, pud_t *pud, unsigned long haddr)
{
    VM_BUG_ON(haddr & ~HPAGE_PUD_MASK);
    VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
    VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PUD_SIZE, vma);
    VM_BUG_ON(!pud_trans_huge(*pud) && !pud_devmap(*pud));

    count_vm_event(THP_SPLIT_PUD);

    pudp_huge_clear_flush_notify(vma, haddr, pud);
}
/* 拆分 大页 上级目录 */
void __split_huge_pud(struct vm_area_struct *vma, pud_t *pud, unsigned long address)
{
    spinlock_t *ptl;
    struct mmu_notifier_range range;

    mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm, address & HPAGE_PUD_MASK,
                            (address & HPAGE_PUD_MASK) + HPAGE_PUD_SIZE);
    mmu_notifier_invalidate_range_start(&range);
    ptl = pud_lock(vma->vm_mm, pud);
    if (unlikely(!pud_trans_huge(*pud) && !pud_devmap(*pud)))
        goto out;
    __split_huge_pud_locked(vma, pud, range.start);

out:
    spin_unlock(ptl);
    /*
	 * No need to double call mmu_notifier->invalidate_range() callback as
	 * the above pudp_huge_clear_flush_notify() did already call it.
	 */
    mmu_notifier_invalidate_range_only_end(&range);
}
#endif /* CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */

static void __split_huge_zero_page_pmd(struct vm_area_struct *vma, unsigned long haddr, pmd_t *pmd)
{
    struct mm_struct *mm = vma->vm_mm;
    pgtable_t pgtable;
    pmd_t _pmd;
    int i;

    /*
	 * Leave pmd empty until pte is filled note that it is fine to delay
	 * notification until mmu_notifier_invalidate_range_end() as we are
	 * replacing a zero pmd write protected page with a zero pte write
	 * protected page.
	 *
	 * See Documentation/vm/mmu_notifier.rst
	 */
    pmdp_huge_clear_flush(vma, haddr, pmd);

    pgtable = pgtable_trans_huge_withdraw(mm, pmd);
    pmd_populate(mm, &_pmd, pgtable);

    for (i = 0; i < HPAGE_PMD_NR; i++, haddr += PAGE_SIZE) {
        pte_t *pte, entry;
        entry = pfn_pte(my_zero_pfn(haddr), vma->vm_page_prot);
        entry = pte_mkspecial(entry);
        pte = pte_offset_map(&_pmd, haddr);
        VM_BUG_ON(!pte_none(*pte));
        set_pte_at(mm, haddr, pte, entry);
        pte_unmap(pte);
    }
    smp_wmb(); /* make pte visible before pmd */
    pmd_populate(mm, pmd, pgtable);
}

static void __split_huge_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd, unsigned long haddr, bool freeze)
{
    struct mm_struct *mm = vma->vm_mm;
    struct page *page;
    pgtable_t pgtable;
    pmd_t old_pmd, _pmd;
    bool young, write, soft_dirty, pmd_migration = false, uffd_wp = false;
    unsigned long addr;
    int i;

    VM_BUG_ON(haddr & ~HPAGE_PMD_MASK);
    VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
    VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PMD_SIZE, vma);
    VM_BUG_ON(!is_pmd_migration_entry(*pmd) && !pmd_trans_huge(*pmd) && !pmd_devmap(*pmd));

    count_vm_event(THP_SPLIT_PMD);

    if (!vma_is_anonymous(vma)) {
        _pmd = pmdp_huge_clear_flush_notify(vma, haddr, pmd);
        /*
		 * We are going to unmap this huge page. So
		 * just go ahead and zap it
		 */
        if (arch_needs_pgtable_deposit())
            zap_deposited_table(mm, pmd);
        if (vma_is_special_huge(vma))
            return;
        page = pmd_page(_pmd);
        if (!PageDirty(page) && pmd_dirty(_pmd))
            set_page_dirty(page);
        if (!PageReferenced(page) && pmd_young(_pmd))
            SetPageReferenced(page);
        page_remove_rmap(page, true);
        put_page(page);
        add_mm_counter(mm, mm_counter_file(page), -HPAGE_PMD_NR);
        return;
    } else if (pmd_trans_huge(*pmd) && is_huge_zero_pmd(*pmd)) {
        /*
		 * FIXME: Do we want to invalidate secondary mmu by calling
		 * mmu_notifier_invalidate_range() see comments below inside
		 * __split_huge_pmd() ?
		 *
		 * We are going from a zero huge page write protected to zero
		 * small page also write protected so it does not seems useful
		 * to invalidate secondary mmu at this time.
		 */
        return __split_huge_zero_page_pmd(vma, haddr, pmd);
    }

    /*
	 * Up to this point the pmd is present and huge and userland has the
	 * whole access to the hugepage during the split (which happens in
	 * place). If we overwrite the pmd with the not-huge version pointing
	 * to the pte here (which of course we could if all CPUs were bug
	 * free), userland could trigger a small page size TLB miss on the
	 * small sized TLB while the hugepage TLB entry is still established in
	 * the huge TLB. Some CPU doesn't like that.
	 * See http://support.amd.com/TechDocs/41322_10h_Rev_Gd.pdf, Erratum
	 * 383 on page 105. Intel should be safe but is also warns that it's
	 * only safe if the permission and cache attributes of the two entries
	 * loaded in the two TLB is identical (which should be the case here).
	 * But it is generally safer to never allow small and huge TLB entries
	 * for the same virtual address to be loaded simultaneously. So instead
	 * of doing "pmd_populate(); flush_pmd_tlb_range();" we first mark the
	 * current pmd notpresent (atomically because here the pmd_trans_huge
	 * must remain set at all times on the pmd until the split is complete
	 * for this pmd), then we flush the SMP TLB and finally we write the
	 * non-huge version of the pmd entry with pmd_populate.
	 */
    old_pmd = pmdp_invalidate(vma, haddr, pmd);

    pmd_migration = is_pmd_migration_entry(old_pmd);
    if (unlikely(pmd_migration)) {
        swp_entry_t entry;

        entry = pmd_to_swp_entry(old_pmd);
        page = pfn_to_page(swp_offset(entry));
        write = is_write_migration_entry(entry);
        young = false;
        soft_dirty = pmd_swp_soft_dirty(old_pmd);
        uffd_wp = pmd_swp_uffd_wp(old_pmd);
    } else {
        page = pmd_page(old_pmd);
        if (pmd_dirty(old_pmd))
            SetPageDirty(page);
        write = pmd_write(old_pmd);
        young = pmd_young(old_pmd);
        soft_dirty = pmd_soft_dirty(old_pmd);
        uffd_wp = pmd_uffd_wp(old_pmd);
    }
    VM_BUG_ON_PAGE(!page_count(page), page);
    page_ref_add(page, HPAGE_PMD_NR - 1);

    /*
	 * Withdraw the table only after we mark the pmd entry invalid.
	 * This's critical for some architectures (Power).
	 */
    pgtable = pgtable_trans_huge_withdraw(mm, pmd);
    pmd_populate(mm, &_pmd, pgtable);

    for (i = 0, addr = haddr; i < HPAGE_PMD_NR; i++, addr += PAGE_SIZE) {
        pte_t entry, *pte;
        /*
		 * Note that NUMA hinting access restrictions are not
		 * transferred to avoid any possibility of altering
		 * permissions across VMAs.
		 */
        if (freeze || pmd_migration) {
            swp_entry_t swp_entry;
            swp_entry = make_migration_entry(page + i, write);
            entry = swp_entry_to_pte(swp_entry);
            if (soft_dirty)
                entry = pte_swp_mksoft_dirty(entry);
            if (uffd_wp)
                entry = pte_swp_mkuffd_wp(entry);
        } else {
            entry = mk_pte(page + i, READ_ONCE(vma->vm_page_prot));
            entry = maybe_mkwrite(entry, vma);
            if (!write)
                entry = pte_wrprotect(entry);
            if (!young)
                entry = pte_mkold(entry);
            if (soft_dirty)
                entry = pte_mksoft_dirty(entry);
            if (uffd_wp)
                entry = pte_mkuffd_wp(entry);
        }
        pte = pte_offset_map(&_pmd, addr);
        BUG_ON(!pte_none(*pte));
        set_pte_at(mm, addr, pte, entry);
        if (!pmd_migration)
            atomic_inc(&page[i]._mapcount);
        pte_unmap(pte);
    }

    if (!pmd_migration) {
        /*
		 * Set PG_double_map before dropping compound_mapcount to avoid
		 * false-negative page_mapped().
		 */
        if (compound_mapcount(page) > 1 && !TestSetPageDoubleMap(page)) {
            for (i = 0; i < HPAGE_PMD_NR; i++)
                atomic_inc(&page[i]._mapcount);
        }

        lock_page_memcg(page);
        if (atomic_add_negative(-1, compound_mapcount_ptr(page))) {
            /* Last compound_mapcount is gone. */
            __dec_lruvec_page_state(page, NR_ANON_THPS);
            if (TestClearPageDoubleMap(page)) {
                /* No need in mapcount reference anymore */
                for (i = 0; i < HPAGE_PMD_NR; i++)
                    atomic_dec(&page[i]._mapcount);
            }
        }
        unlock_page_memcg(page);
    }

    smp_wmb(); /* make pte visible before pmd */
    pmd_populate(mm, pmd, pgtable);

    if (freeze) {
        for (i = 0; i < HPAGE_PMD_NR; i++) {
            page_remove_rmap(page + i, false);
            put_page(page + i);
        }
    }
}

void __split_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd, unsigned long address, bool freeze, struct page *page)
{
    spinlock_t *ptl;
    struct mmu_notifier_range range;
    bool was_locked = false;
    pmd_t _pmd;

    mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm, address & HPAGE_PMD_MASK,
                            (address & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE);
    mmu_notifier_invalidate_range_start(&range);
    ptl = pmd_lock(vma->vm_mm, pmd);

    /*
	 * If caller asks to setup a migration entries, we need a page to check
	 * pmd against. Otherwise we can end up replacing wrong page.
	 */
    VM_BUG_ON(freeze && !page);
    if (page) {
        VM_WARN_ON_ONCE(!PageLocked(page));
        was_locked = true;
        if (page != pmd_page(*pmd))
            goto out;
    }

repeat:
    if (pmd_trans_huge(*pmd)) {
        if (!page) {
            page = pmd_page(*pmd);
            if (unlikely(!trylock_page(page))) {
                get_page(page);
                _pmd = *pmd;
                spin_unlock(ptl);
                lock_page(page);
                spin_lock(ptl);
                if (unlikely(!pmd_same(*pmd, _pmd))) {
                    unlock_page(page);
                    put_page(page);
                    page = NULL;
                    goto repeat;
                }
                put_page(page);
            }
        }
        if (PageMlocked(page))
            clear_page_mlock(page);
    } else if (!(pmd_devmap(*pmd) || is_pmd_migration_entry(*pmd)))
        goto out;
    __split_huge_pmd_locked(vma, pmd, range.start, freeze);
out:
    spin_unlock(ptl);
    if (!was_locked && page)
        unlock_page(page);
    /*
	 * No need to double call mmu_notifier->invalidate_range() callback.
	 * They are 3 cases to consider inside __split_huge_pmd_locked():
	 *  1) pmdp_huge_clear_flush_notify() call invalidate_range() obvious
	 *  2) __split_huge_zero_page_pmd() read only zero page and any write
	 *    fault will trigger a flush_notify before pointing to a new page
	 *    (it is fine if the secondary mmu keeps pointing to the old zero
	 *    page in the meantime)
	 *  3) Split a huge pmd into pte pointing to the same page. No need
	 *     to invalidate secondary tlb entry they are all still valid.
	 *     any further changes to individual pte will notify. So no need
	 *     to call mmu_notifier->invalidate_range()
	 */
    mmu_notifier_invalidate_range_only_end(&range);
}

void split_huge_pmd_address(struct vm_area_struct *vma, unsigned long address, bool freeze, struct page *page)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset(vma->vm_mm, address);
    if (!pgd_present(*pgd))
        return;

    p4d = p4d_offset(pgd, address);
    if (!p4d_present(*p4d))
        return;

    pud = pud_offset(p4d, address);
    if (!pud_present(*pud))
        return;

    pmd = pmd_offset(pud, address);

    __split_huge_pmd(vma, pmd, address, freeze, page);
}

void vma_adjust_trans_huge(struct vm_area_struct *vma, unsigned long start, unsigned long end, long adjust_next)
{
    /*
	 * If the new start address isn't hpage aligned and it could
	 * previously contain an hugepage: check if we need to split
	 * an huge pmd.
	 */
    if (start & ~HPAGE_PMD_MASK && (start & HPAGE_PMD_MASK) >= vma->vm_start &&
        (start & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE <= vma->vm_end)
        split_huge_pmd_address(vma, start, false, NULL);

    /*
	 * If the new end address isn't hpage aligned and it could
	 * previously contain an hugepage: check if we need to split
	 * an huge pmd.
	 */
    if (end & ~HPAGE_PMD_MASK && (end & HPAGE_PMD_MASK) >= vma->vm_start &&
        (end & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE <= vma->vm_end)
        split_huge_pmd_address(vma, end, false, NULL);

    /*
	 * If we're also updating the vma->vm_next->vm_start, if the new
	 * vm_next->vm_start isn't hpage aligned and it could previously
	 * contain an hugepage: check if we need to split an huge pmd.
	 */
    if (adjust_next > 0) {
        struct vm_area_struct *next = vma->vm_next;
        unsigned long nstart = next->vm_start;
        nstart += adjust_next;
        if (nstart & ~HPAGE_PMD_MASK && (nstart & HPAGE_PMD_MASK) >= next->vm_start &&
            (nstart & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE <= next->vm_end)
            split_huge_pmd_address(next, nstart, false, NULL);
    }
}

static void unmap_page(struct page *page)
{
    enum ttu_flags ttu_flags = TTU_IGNORE_MLOCK | TTU_RMAP_LOCKED | TTU_SPLIT_HUGE_PMD;
    bool unmap_success;

    // 如果不是大页的头页面，触发bug
    VM_BUG_ON_PAGE(!PageHead(page), page);

    // 是匿名透明大页，设置TTU_SPLIT_FREEZE标志
    if (PageAnon(page))
        ttu_flags |= TTU_SPLIT_FREEZE;

    unmap_success = try_to_unmap(page, ttu_flags);
    VM_BUG_ON_PAGE(!unmap_success, page);
}

// 将迁移页表项重新映射为正常的页表项
static void remap_page(struct page *page, unsigned int nr)
{
    int i;
    // 如果是大页，只处理首页？
    if (PageTransHuge(page)) {
        // new 为啥也是page?
        remove_migration_ptes(page, page, true);
    } else {
        for (i = 0; i < nr; i++)
            remove_migration_ptes(page + i, page + i, true);
    }
}

/**
   拆分大页(应该就是透明大页吧？HugeTLB大页还有被拆分的场景？)
* │   * @head: 指向大页头的指针                                         │
│   * @tail: 要拆分的尾部页面的索引                                   │
│   * @lruvec: 大页的首页面所在的LRU链表的向量                                  │
│   * @list: 指向将要存放拆分后普通页面的链表
 * */
static void __split_huge_page_tail(struct page *head, int tail, struct lruvec *lruvec, struct list_head *list)
{
    // 当前正在处理的大页的尾页
    struct page *page_tail = head + tail;

    VM_BUG_ON_PAGE(atomic_read(&page_tail->_mapcount) != -1, page_tail);

    /*
	 * Clone page flags before unfreezing refcount.
	 *
	 * After successful get_page_unless_zero() might follow flags change,
	 * for exmaple lock_page() which set PG_waiters.
	 */
    page_tail->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
    // 从首节点上继承一些标志位
    page_tail->flags |= (head->flags & ((1L << PG_referenced) | (1L << PG_swapbacked) | (1L << PG_swapcache) |
                                        (1L << PG_mlocked) | (1L << PG_uptodate) | (1L << PG_active) |
                                        (1L << PG_workingset) | (1L << PG_locked) | (1L << PG_unevictable) |
#ifdef CONFIG_64BIT
                                        (1L << PG_arch_2) |
#endif
                                        (1L << PG_dirty)));

    /* ->mapping in first tail page is compound_mapcount */
    VM_BUG_ON_PAGE(tail > 2 && page_tail->mapping != TAIL_MAPPING, page_tail);
    page_tail->mapping = head->mapping;
    // TODO:没看懂
    page_tail->index = head->index + tail;

    /* Page flags must be visible before we make the page non-compound. */
    smp_wmb();

    /*
	 * Clear PageTail before unfreezing page refcount.
	 *
	 * After successful get_page_unless_zero() might follow put_page()
	 * which needs correct compound_head().
	 */
    clear_compound_head(page_tail);

    /* Finally unfreeze refcount. Additional reference from page cache. */
    page_ref_unfreeze(page_tail, 1 + (!PageAnon(head) || PageSwapCache(head)));

    if (page_is_young(head))
        set_page_young(page_tail);
    if (page_is_idle(head))
        set_page_idle(page_tail);

    page_cpupid_xchg_last(page_tail, page_cpupid_last(head));

    /*
	 * always add to the tail because some iterators expect new
	 * pages to show after the currently processed elements - e.g.
	 * migrate_pages
	 */
    lru_add_page_tail(head, page_tail, lruvec, list);
}

/**
    * @page: 指向要拆分的大页的指针
    * @list: 指向将要存放拆分后普通页面的链表
*    - 如果提供了list参数,将拆分后的页面添加到该链表
*    - 如果list为NULL,则添加到首页对应的LRU链表
    * @end: 拆分操作的结束页框偏移
    * @flags: 拆分操作的标志位
 * *
 * */
// 拆分透明大页，list传来的是null
static void __split_huge_page(struct page *page, struct list_head *list, pgoff_t end, unsigned long flags)
{
    /* 获取复合页的头页 */
    struct page *head = compound_head(page);
    /* 获取页所在的节点 */
    pg_data_t *pgdat = page_pgdat(head);
    /* LRU链表向量 */
    struct lruvec *lruvec;
    /* 交换缓存地址空间 */
    struct address_space *swap_cache = NULL;
    /* 交换分区偏移量 */
    unsigned long offset = 0;
    /* 大页包含的普通页面数量 */
    unsigned int nr = thp_nr_pages(head);
    int i;

    /* 获取页面所属的LRU链表向量 */
    lruvec = mem_cgroup_page_lruvec(head, pgdat);
    /* 在将页面添加到LRU之前完成内存控制组(memcg)的处理 */
    mem_cgroup_split_huge_fixup(head);

    // 首页是处于交换缓存中的匿名页
    if (PageAnon(head) && PageSwapCache(head)) {
        /* 获取交换项 */
        // PG_swapcache：页面处于交换缓存中，private指向swp_entry_t
        swp_entry_t entry = { .val = page_private(head) };
        /* 获取交换分区偏移量 */
        offset = swp_offset(entry);
        /* 获取交换缓存的地址空间 */
        swap_cache = swap_address_space(entry);
        /* 锁定交换缓存的页面树 */
        xa_lock(&swap_cache->i_pages);
    }

    // 处理所有尾页
    for (i = nr - 1; i >= 1; i--) {
        /* 拆分子页面 */
        // 将尾页都添加到首页之前所在的lru链表中（如果list==null）
        __split_huge_page_tail(head, i, lruvec, list);

        /* 处理超出文件大小的页面:从页面缓存中删除 */
        if (head[i].index >= end) {
            ClearPageDirty(head + i);
            __delete_from_page_cache(head + i, NULL);
            /* 如果启用了SHMEM且是swap backed页面,减少共享内存计数 */
            if (IS_ENABLED(CONFIG_SHMEM) && PageSwapBacked(head))
                shmem_uncharge(head->mapping->host, 1);
            put_page(head + i);
        }
        /* 如果不是匿名页面,将页面存储到文件映射的基数树中 */
        else if (!PageAnon(page)) {
            __xa_store(&head->mapping->i_pages, head[i].index, head + i, 0);
        }
        /* 如果是匿名页面且在交换缓存中,将页面重新存储到交换缓存的基数树中 */
        else if (swap_cache) {
            __xa_store(&swap_cache->i_pages, offset + i, head + i, 0);
        }
    }

    /* 清除复合页标志 */
    ClearPageCompound(head);
    /* 拆分页面所有者信息(用于调试) */
    split_page_owner(head, nr);

    /* 根据页面类型增加引用计数并解锁相应的基数树 */
    if (PageAnon(head)) {
        if (PageSwapCache(head)) {
            page_ref_add(head, 2);
            xa_unlock(&swap_cache->i_pages);
        } else {
            page_ref_inc(head);
        }
    } else {
        page_ref_add(head, 2);
        xa_unlock(&head->mapping->i_pages);
    }

    /* 解锁节点的LRU锁 */
    spin_unlock_irqrestore(&pgdat->lru_lock, flags);

    /* 重新映射页面 */
    // 为啥是head呢
    // TODO:
    remap_page(head, nr);

    /* 如果首页面在交换缓存中,拆分交换簇 */
    if (PageSwapCache(head)) {
        swp_entry_t entry = { .val = page_private(head) };
        split_swap_cluster(entry);
    }

    /* 处理除了请求页面外的所有子页面 */
    for (i = 0; i < nr; i++) {
        struct page *subpage = head + i;
        if (subpage == page)
            continue;
        /* 解锁子页面 */
        unlock_page(subpage);
        /* 释放子页面的引用 */
        put_page(subpage);
    }
}

/**
 *  获取 page->_mapcount
 */
int total_mapcount(struct page *page)
{
    int i, compound, nr, ret;

    VM_BUG_ON_PAGE(PageTail(page), page);

    if (likely(!PageCompound(page)))
        return atomic_read(&page->_mapcount) + 1;

    /* 页面数 */
    compound = compound_mapcount(page);
    nr = compound_nr(page); /* 复合页面中包含多少 标准 page */

    /* 如果是大页，直接返回 */
    if (PageHuge(page))
        return compound;

    /* 初始化 mapcount 为 复合页 个数 */
    ret = compound;

    /* 遍历 所有标准 page */
    for (i = 0; i < nr; i++)
        ret += atomic_read(&page[i]._mapcount) + 1;

    /**
	 *  File pages has compound_mapcount included in _mapcount
	 *
	 *  如果不是匿名映射，即为 文件映射
	 *  文件page 在 _mapcount 中 已经包含了  compound_mapcount
	 */
    if (!PageAnon(page))
        return ret - compound * nr;

    if (PageDoubleMap(page))
        ret -= nr;

    return ret;
}

/*
 * This calculates accurately how many mappings a transparent hugepage
 * has (unlike page_mapcount() which isn't fully accurate). This full
 * accuracy is primarily needed to know if copy-on-write faults can
 * reuse the page and change the mapping to read-write instead of
 * copying them. At the same time this returns the total_mapcount too.
 *
 * The function returns the highest mapcount any one of the subpages
 * has. If the return value is one, even if different processes are
 * mapping different subpages of the transparent hugepage, they can
 * all reuse it, because each process is reusing a different subpage.
 *
 * The total_mapcount is instead counting all virtual mappings of the
 * subpages. If the total_mapcount is equal to "one", it tells the
 * caller all mappings belong to the same "mm" and in turn the
 * anon_vma of the transparent hugepage can become the vma->anon_vma
 * local one as no other process may be mapping any of the subpages.
 *
 * It would be more accurate to replace page_mapcount() with
 * page_trans_huge_mapcount(), however we only use
 * page_trans_huge_mapcount() in the copy-on-write faults where we
 * need full accuracy to avoid breaking page pinning, because
 * page_trans_huge_mapcount() is slower than page_mapcount().
 */
int page_trans_huge_mapcount(struct page *page, int *total_mapcount)
{
    int i, ret, _total_mapcount, mapcount;

    /* hugetlbfs shouldn't call it */
    VM_BUG_ON_PAGE(PageHuge(page), page);

    if (likely(!PageTransCompound(page))) {
        mapcount = atomic_read(&page->_mapcount) + 1;
        if (total_mapcount)
            *total_mapcount = mapcount;
        return mapcount;
    }

    page = compound_head(page);

    _total_mapcount = ret = 0;
    for (i = 0; i < thp_nr_pages(page); i++) {
        mapcount = atomic_read(&page[i]._mapcount) + 1;
        ret = max(ret, mapcount);
        _total_mapcount += mapcount;
    }
    if (PageDoubleMap(page)) {
        ret -= 1;
        _total_mapcount -= thp_nr_pages(page);
    }
    mapcount = compound_mapcount(page);
    ret += mapcount;
    _total_mapcount += mapcount;
    if (total_mapcount)
        *total_mapcount = _total_mapcount;
    return ret;
}

/* Racy check whether the huge page can be split */
// 检查透明大页是否可以被拆分
bool can_split_huge_page(struct page *page, int *pextra_pins)
{
    int extra_pins;

    /* Additional pins from page cache */
    if (PageAnon(page))
        // 透明大页的换出是整个大页的所有子页都会被换出吧
        // 应该是
        // 所以当当前page在
        extra_pins = PageSwapCache(page) ? thp_nr_pages(page) : 0;
    else
        extra_pins = thp_nr_pages(page);
    if (pextra_pins)
        *pextra_pins = extra_pins;
    return total_mapcount(page) == page_count(page) - extra_pins - 1;
}

/*
 * This function splits huge page into normal pages. @page can point to any
 * subpage of huge page to split. Split doesn't change the position of @page.
 *
 * Only caller must hold pin on the @page, otherwise split fails with -EBUSY.
 * The huge page must be locked.
 *
 * If @list is null, tail pages will be added to LRU list, otherwise, to @list.
 *
 * Both head page and tail pages will inherit mapping, flags, and so on from
 * the hugepage.
 *
 * GUP pin and PG_locked transferred to @page. Rest subpages can be freed if
 * they are not mapped.
 *
 * Returns 0 if the hugepage is split successfully.
 * Returns -EBUSY if the page is pinned or if anon_vma disappeared from under
 * us.
 */
/**
  * * 这个函数将大页拆分为普通页面。@page                        │
│  可以指向大页的任何子页面进行拆分。                            │
│   * 拆分不会改变 @page 的位置。                                │
│   *                                                            │
│   * 调用者必须持有 @page 的引用计数，否则拆分将失败并返回  │
│  -EBUSY。                                                      │
│   * 大页必须被锁定。                                           │
│   *                                                            │
│   * 如果 @list 为 null，尾部页面将被添加到 LRU                 │
│  列表中，否则将添加到 @list。                                  │
│   *                                                            │
│   * 头页面和尾页面将从大页继承映射、标志等信息。               │
│   *                                                            │
│   * GUP 引用和 PG_locked 状态将转移到                          │
│  @page。其余子页面可以在未映射时被释放。                       │
│   *                                                            │
│   * 如果大页成功拆分，则返回 0。                               │
│   *                                                            │
│  如果页面被锁定或匿名虚拟内存区域（anon_vma）在我们操作期间消  │
│  ，则返回 -EBUSY。  
  *  */

/**
* split_huge_page_to_list - 将透明大页拆分为标准页面
* @page: 要拆分的透明大页中的任意页面指针
* @list: 拆分后的尾页添加到此链表,为NULL时添加到首页的LRU链表
*
* 详细说明:
* 本函数用于将一个透明大页(THP)拆分为多个标准页面。拆分过程如下：
* 1. 首先检查页面状态(是否锁定、是否可写回等)
* 2. 获取并检查页面的引用计数
* 3. 解除所有页表映射关系
* 4. 对每个标准页面:
*   - 继承原透明大页的属性(mapping/index等)
*   - 设置适当的引用计数
*   - 添加到指定链表或LRU
* 5. 清除原透明大页的复合页标记
* 6. 重建页表映射
*
* 调用要求:
* 1. 调用者必须持有page的引用计数,否则返回-EBUSY
* 2. page必须已经上锁(PageLocked)
*
* 返回值:
* - 0: 拆分成功
* - -EBUSY: page被pin或匿名内存区域消失
*
* 注意事项:
* 1. 本函数存在竞态条件,拆分前会再次检查页面状态
* 2. 拆分过程会临时禁止其他进程访问这些页面
* 3. 必须在持有适当锁的情况下调用此函数
*/
// 拆分透明大页的参数设置：split_huge_page_to_list(page, NULL);
int split_huge_page_to_list(struct page *page, struct list_head *list)
{
    // 获取透明大页的首页(compound head)
    struct page *head = compound_head(page);
    // 获取页面所在NUMA节点的数据结构
    struct pglist_data *pgdata = NODE_DATA(page_to_nid(head));
    // 获取延迟拆分队列
    struct deferred_split *ds_queue = get_deferred_split_queue(head);
    // 匿名内存区域结构指针,初始为NULL
    struct anon_vma *anon_vma = NULL;
    // 文件映射的地址空间结构指针,初始为NULL
    struct address_space *mapping = NULL;
    // 声明计数、映射计数、额外引用计数和返回值变量
    int count, mapcount, extra_pins, ret;
    // 中断标志
    unsigned long flags;
    // 文件映射的结束位置
    pgoff_t end;

    // 验证:不能是零页、必须已锁定、必须是复合页
    VM_BUG_ON_PAGE(is_huge_zero_page(head), head);
    VM_BUG_ON_PAGE(!PageLocked(head), head);
    VM_BUG_ON_PAGE(!PageCompound(head), head);

    // 如果页面正在写回,返回繁忙
    if (PageWriteback(head))
        return -EBUSY;

    // 处理匿名页面的情况
    if (PageAnon(head)) {
        // 透明大页应该是一定走到这个判断，而不是下面那个分支
        // 获取并锁定匿名内存区域
        anon_vma = page_get_anon_vma(head);
        if (!anon_vma) {
            ret = -EBUSY;
            goto out;
        }
        end = -1;
        mapping = NULL;
        // 对匿名内存区域加写锁
        anon_vma_lock_write(anon_vma);
    } else {
        // 处理文件映射页面的情况
        mapping = head->mapping;
        if (!mapping) {
            ret = -EBUSY;
            goto out;
        }
        // 对文件映射加读锁
        anon_vma = NULL;
        i_mmap_lock_read(mapping);
        // 计算文件映射的结束位置
        end = DIV_ROUND_UP(i_size_read(mapping->host), PAGE_SIZE);
    }

    // 检查页面是否可以拆分(存在竞态)
    if (!can_split_huge_page(head, &extra_pins)) {
        ret = -EBUSY;
        goto out_unlock;
    }

    // 解除对首页的页表映射
    // 后面啥时候应该会设置为迁移页表项
    unmap_page(head);
    VM_BUG_ON_PAGE(compound_mapcount(head), head);

    // 锁定LRU链表,防止并发访问
    spin_lock_irqsave(&pgdata->lru_lock, flags);

    // 如果是文件映射,检查页面是否在页缓存中
    if (mapping) {
        XA_STATE(xas, &mapping->i_pages, page_index(head));
        xa_lock(&mapping->i_pages);
        if (xas_load(&xas) != head)
            goto fail;
    }

    // 锁定延迟拆分队列,防止deferred_split_scan()修改引用计数
    spin_lock(&ds_queue->split_queue_lock);
    count = page_count(head);
    mapcount = total_mapcount(head);

    // 如果没有映射且可以冻结页面引用计数
    if (!mapcount && page_ref_freeze(head, 1 + extra_pins)) {
        // 如果在延迟拆分队列中,从队列移除
        if (!list_empty(page_deferred_list(head))) {
            ds_queue->split_queue_len--;
            list_del(page_deferred_list(head));
        }
        spin_unlock(&ds_queue->split_queue_lock);

        // 更新统计信息
        if (mapping) {
            if (PageSwapBacked(head))
                __dec_node_page_state(head, NR_SHMEM_THPS);
            else
                __dec_node_page_state(head, NR_FILE_THPS);
        }

        // 执行实际的拆分操作
        __split_huge_page(page, list, end, flags);
        ret = 0;
    } else {
        // 拆分失败的调试信息和错误处理
        if (IS_ENABLED(CONFIG_DEBUG_VM) && mapcount) {
            pr_alert("total_mapcount: %u, page_count(): %u\n", mapcount, count);
            if (PageTail(page))
                dump_page(head, NULL);
            dump_page(page, "total_mapcount(head) > 0");
            BUG();
        }
        spin_unlock(&ds_queue->split_queue_lock);
    fail:
        if (mapping)
            xa_unlock(&mapping->i_pages);
        spin_unlock_irqrestore(&pgdata->lru_lock, flags);
        // 恢复页表映射
        remap_page(head, thp_nr_pages(head));
        ret = -EBUSY;
    }

out_unlock:
    // 释放锁和清理工作
    if (anon_vma) {
        anon_vma_unlock_write(anon_vma);
        put_anon_vma(anon_vma);
    }
    if (mapping)
        i_mmap_unlock_read(mapping);
out:
    // 更新统计信息并返回
    count_vm_event(!ret ? THP_SPLIT_PAGE : THP_SPLIT_PAGE_FAILED);
    return ret;
}

void free_transhuge_page(struct page *page)
{
    struct deferred_split *ds_queue = get_deferred_split_queue(page);
    unsigned long flags;

    spin_lock_irqsave(&ds_queue->split_queue_lock, flags);
    if (!list_empty(page_deferred_list(page))) {
        ds_queue->split_queue_len--;
        list_del(page_deferred_list(page));
    }
    spin_unlock_irqrestore(&ds_queue->split_queue_lock, flags);
    free_compound_page(page);
}

void deferred_split_huge_page(struct page *page)
{
    struct deferred_split *ds_queue = get_deferred_split_queue(page);
#ifdef CONFIG_MEMCG
    struct mem_cgroup *memcg = compound_head(page)->mem_cgroup;
#endif
    unsigned long flags;

    VM_BUG_ON_PAGE(!PageTransHuge(page), page);

    /*
	 * The try_to_unmap() in page reclaim path might reach here too,
	 * this may cause a race condition to corrupt deferred split queue.
	 * And, if page reclaim is already handling the same page, it is
	 * unnecessary to handle it again in shrinker.
	 *
	 * Check PageSwapCache to determine if the page is being
	 * handled by page reclaim since THP swap would add the page into
	 * swap cache before calling try_to_unmap().
	 */
    if (PageSwapCache(page))
        return;

    spin_lock_irqsave(&ds_queue->split_queue_lock, flags);
    if (list_empty(page_deferred_list(page))) {
        count_vm_event(THP_DEFERRED_SPLIT_PAGE);
        list_add_tail(page_deferred_list(page), &ds_queue->split_queue);
        ds_queue->split_queue_len++;
#ifdef CONFIG_MEMCG
        if (memcg)
            memcg_set_shrinker_bit(memcg, page_to_nid(page), deferred_split_shrinker.id);
#endif
    }
    spin_unlock_irqrestore(&ds_queue->split_queue_lock, flags);
}

static unsigned long deferred_split_count(struct shrinker *shrink, struct shrink_control *sc)
{
    struct pglist_data *pgdata = NODE_DATA(sc->nid);
    struct deferred_split *ds_queue = &pgdata->deferred_split_queue;

#ifdef CONFIG_MEMCG
    if (sc->memcg)
        ds_queue = &sc->memcg->deferred_split_queue;
#endif
    return READ_ONCE(ds_queue->split_queue_len);
}

static unsigned long deferred_split_scan(struct shrinker *shrink, struct shrink_control *sc)
{
    struct pglist_data *pgdata = NODE_DATA(sc->nid);
    struct deferred_split *ds_queue = &pgdata->deferred_split_queue;
    unsigned long flags;
    LIST_HEAD(list), *pos, *next;
    struct page *page;
    int split = 0;

#ifdef CONFIG_MEMCG
    if (sc->memcg)
        ds_queue = &sc->memcg->deferred_split_queue;
#endif

    spin_lock_irqsave(&ds_queue->split_queue_lock, flags);
    /* Take pin on all head pages to avoid freeing them under us */
    list_for_each_safe(pos, next, &ds_queue->split_queue)
    {
        page = list_entry((void *)pos, struct page, mapping);
        page = compound_head(page);
        if (get_page_unless_zero(page)) {
            list_move(page_deferred_list(page), &list);
        } else {
            /* We lost race with put_compound_page() */
            list_del_init(page_deferred_list(page));
            ds_queue->split_queue_len--;
        }
        if (!--sc->nr_to_scan)
            break;
    }
    spin_unlock_irqrestore(&ds_queue->split_queue_lock, flags);

    list_for_each_safe(pos, next, &list)
    {
        page = list_entry((void *)pos, struct page, mapping);
        if (!trylock_page(page))
            goto next;
        /* split_huge_page() removes page from list on success */
        if (!split_huge_page(page))
            split++;
        unlock_page(page);
    next:
        put_page(page);
    }

    spin_lock_irqsave(&ds_queue->split_queue_lock, flags);
    list_splice_tail(&list, &ds_queue->split_queue);
    spin_unlock_irqrestore(&ds_queue->split_queue_lock, flags);

    /*
	 * Stop shrinker if we didn't split any page, but the queue is empty.
	 * This can happen if pages were freed under us.
	 */
    if (!split && list_empty(&ds_queue->split_queue))
        return SHRINK_STOP;
    return split;
}

static struct shrinker deferred_split_shrinker = {
    .count_objects = deferred_split_count,
    .scan_objects = deferred_split_scan,
    .seeks = DEFAULT_SEEKS,
    .flags = SHRINKER_NUMA_AWARE | SHRINKER_MEMCG_AWARE | SHRINKER_NONSLAB,
};

#ifdef CONFIG_DEBUG_FS
static int split_huge_pages_set(void *data, u64 val)
{
    struct zone *zone;
    struct page *page;
    unsigned long pfn, max_zone_pfn;
    unsigned long total = 0, split = 0;

    if (val != 1)
        return -EINVAL;

    for_each_populated_zone(zone)
    {
        max_zone_pfn = zone_end_pfn(zone);
        for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++) {
            if (!pfn_valid(pfn))
                continue;

            page = pfn_to_page(pfn);
            if (!get_page_unless_zero(page))
                continue;

            if (zone != page_zone(page))
                goto next;

            if (!PageHead(page) || PageHuge(page) || !PageLRU(page))
                goto next;

            total++;
            lock_page(page);
            if (!split_huge_page(page))
                split++;
            unlock_page(page);
        next:
            put_page(page);
        }
    }

    pr_info("%lu of %lu THP split\n", split, total);

    return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(split_huge_pages_fops, NULL, split_huge_pages_set, "%llu\n");

static int __init split_huge_pages_debugfs(void)
{
    debugfs_create_file("split_huge_pages", 0200, NULL, NULL, &split_huge_pages_fops);
    return 0;
}
late_initcall(split_huge_pages_debugfs);
#endif

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
void set_pmd_migration_entry(struct page_vma_mapped_walk *pvmw, struct page *page)
{
    struct vm_area_struct *vma = pvmw->vma;
    struct mm_struct *mm = vma->vm_mm;
    unsigned long address = pvmw->address;
    pmd_t pmdval;
    swp_entry_t entry;
    pmd_t pmdswp;

    if (!(pvmw->pmd && !pvmw->pte))
        return;

    flush_cache_range(vma, address, address + HPAGE_PMD_SIZE);
    pmdval = pmdp_invalidate(vma, address, pvmw->pmd);
    if (pmd_dirty(pmdval))
        set_page_dirty(page);
    entry = make_migration_entry(page, pmd_write(pmdval));
    pmdswp = swp_entry_to_pmd(entry);
    if (pmd_soft_dirty(pmdval))
        pmdswp = pmd_swp_mksoft_dirty(pmdswp);
    set_pmd_at(mm, address, pvmw->pmd, pmdswp);
    page_remove_rmap(page, true);
    put_page(page);
}

void remove_migration_pmd(struct page_vma_mapped_walk *pvmw, struct page *new)
{
    struct vm_area_struct *vma = pvmw->vma;
    struct mm_struct *mm = vma->vm_mm;
    unsigned long address = pvmw->address;
    unsigned long mmun_start = address & HPAGE_PMD_MASK;
    pmd_t pmde;
    swp_entry_t entry;

    if (!(pvmw->pmd && !pvmw->pte))
        return;

    entry = pmd_to_swp_entry(*pvmw->pmd);
    get_page(new);
    pmde = pmd_mkold(mk_huge_pmd(new, vma->vm_page_prot));
    if (pmd_swp_soft_dirty(*pvmw->pmd))
        pmde = pmd_mksoft_dirty(pmde);
    if (is_write_migration_entry(entry))
        pmde = maybe_pmd_mkwrite(pmde, vma);

    flush_cache_range(vma, mmun_start, mmun_start + HPAGE_PMD_SIZE);
    if (PageAnon(new))
        page_add_anon_rmap(new, vma, mmun_start, true);
    else
        page_add_file_rmap(new, true);
    set_pmd_at(mm, mmun_start, pvmw->pmd, pmde);
    if ((vma->vm_flags & VM_LOCKED) && !PageDoubleMap(new))
        mlock_vma_page(new);
    update_mmu_cache_pmd(vma, address, pvmw->pmd);
}
#endif
