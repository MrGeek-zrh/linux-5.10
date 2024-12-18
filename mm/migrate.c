// SPDX-License-Identifier: GPL-2.0
/*
 * Memory Migration functionality - linux/mm/migrate.c
 *
 * Copyright (C) 2006 Silicon Graphics, Inc., Christoph Lameter
 *
 * Page migration was first developed in the context of the memory hotplug
 * project. The main authors of the migration code are:
 *
 * IWAMOTO Toshihiro <iwamoto@valinux.co.jp>
 * Hirokazu Takahashi <taka@valinux.co.jp>
 * Dave Hansen <haveblue@us.ibm.com>
 * Christoph Lameter
 */

#include <linux/migrate.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/nsproxy.h>
#include <linux/pagevec.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/writeback.h>
#include <linux/mempolicy.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/compaction.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/gfp.h>
#include <linux/pagewalk.h>
#include <linux/pfn_t.h>
#include <linux/memremap.h>
#include <linux/userfaultfd_k.h>
#include <linux/balloon_compaction.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/page_owner.h>
#include <linux/sched/mm.h>
#include <linux/ptrace.h>
#include <linux/oom.h>

#include <asm/tlbflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/migrate.h>

#include "internal.h"

/*
 * migrate_prep() needs to be called before we start compiling a list of pages
 * to be migrated using isolate_lru_page(). If scheduling work on other CPUs is
 * undesirable, use migrate_prep_local()
 */
int migrate_prep(void)
{
    /*
	 * Clear the LRU lists so pages can be isolated.
	 * Note that pages may be moved off the LRU after we have
	 * drained them. Those pages will fail to migrate like other
	 * pages that may be busy.
	 */
    lru_add_drain_all();

    return 0;
}

/* Do the necessary work of migrate_prep but not if it involves other CPUs */
int migrate_prep_local(void)
{
    lru_add_drain();

    return 0;
}

/**
 *  隔离movable 页面，设置page的PG_isolated
 *
 *  TODO:隔离movable页面到底是做了什么？目的是什么？
        见 https://kdocs.cn/l/cduWxeNIroSi
 */
int isolate_movable_page(struct page *page, isolate_mode_t mode)
{
    struct address_space *mapping;
    /*
    * 避免处理那些正在被__free_pages()释放的页面，
    * 或者刚刚在我们处理过程中被释放的页面。
    *
    * 如果我们在页面被释放过程中"赢得"了竞争，提高了它的引用计数从而阻止了
    * __free_pages()完成工作，那么在这个代码块最后的put_page()将负责释放
    * 这个页面，从而避免内存泄漏。
    */
    if (unlikely(!get_page_unless_zero(page)))
        goto out;
    /*
    * 在获取PG_lock之前检查PageMovable，因为页面的所有者
    * 假定没有人会触碰新分配页面的PG_lock，
    * 所以无条件地获取锁会破坏页面所有者端的逻辑。
    */
    if (unlikely(!__PageMovable(page)))
        goto out_putpage;
    /*
    * 由于可移动页面没有从LRU列表中隔离，并发的
    * 压缩线程可能会与页面迁移函数发生竞争，
    * 同时也可能与页面释放发生竞争。
    *
    * 为了避免已经隔离的可移动页面在迁移过程中被（错误地）
    * 重新隔离，或者避免试图隔离正在被释放的页面，
    * 让我们在继续可移动页面隔离步骤之前确保我们持有页面锁。
    */
    if (unlikely(!trylock_page(page)))
        goto out_putpage;
    // 不是non-lru movable page，或者已经被其他代码设置为PG_isolated
    if (!PageMovable(page) || PageIsolated(page))
        goto out_no_isolated;

    mapping = page_mapping(page);
    VM_BUG_ON_PAGE(!mapping, page);
    // 调用回调函数进行隔离
    if (!mapping->a_ops->isolate_page(page, mode))
        // 隔离失败
        goto out_no_isolated;
    /* 驱动程序不应该使用page->flags中的PG_isolated位 */
    WARN_ON_ONCE(PageIsolated(page));
    __SetPageIsolated(page);
    unlock_page(page);
    return 0;
out_no_isolated:
    unlock_page(page);
out_putpage:
    put_page(page);
out:
    return -EBUSY;
}

/* It should be called on page which is PG_movable */
void putback_movable_page(struct page *page)
{
    struct address_space *mapping;

    VM_BUG_ON_PAGE(!PageLocked(page), page);
    VM_BUG_ON_PAGE(!PageMovable(page), page);
    VM_BUG_ON_PAGE(!PageIsolated(page), page);

    mapping = page_mapping(page);
    mapping->a_ops->putback_page(page);
    __ClearPageIsolated(page);
}

/*
 * Put previously isolated pages back onto the appropriate lists
 * from where they were once taken off for compaction/migration.
 *
 * This function shall be used whenever the isolated pageset has been
 * built from lru, balloon, hugetlbfs page. See isolate_migratepages_range()
 * and isolate_huge_page().
 *
 *  把已经 分离的页面 重新 添加到LRU 链表中
 */
void putback_movable_pages(struct list_head *l)
{
    struct page *page;
    struct page *page2;

    list_for_each_entry_safe(page, page2, l, lru)
    {
        if (unlikely(PageHuge(page))) {
            putback_active_hugepage(page);
            continue;
        }
        list_del(&page->lru);
        /*
		 * We isolated non-lru movable page so here we can use
		 * __PageMovable because LRU page's mapping cannot have
		 * PAGE_MAPPING_MOVABLE.
		 */
        if (unlikely(__PageMovable(page))) {
            VM_BUG_ON_PAGE(!PageIsolated(page), page);
            lock_page(page);
            if (PageMovable(page))
                putback_movable_page(page);
            else
                __ClearPageIsolated(page);
            unlock_page(page);
            put_page(page);
        } else {
            mod_node_page_state(page_pgdat(page), NR_ISOLATED_ANON + page_is_file_lru(page), -thp_nr_pages(page));
            putback_lru_page(page);
        }
    }
}

/*
 * Restore a potential migration pte to a working pte entry
 *
 * 迁移页表
 */
static bool remove_migration_pte(struct page *page, struct vm_area_struct *vma, unsigned long addr, void *old)
{
    /**
     *  
     */
    struct page_vma_mapped_walk pvmw = {
        pvmw.page = old,
        pvmw.vma = vma,
        pvmw.address = addr,
        pvmw.flags = PVMW_SYNC | PVMW_MIGRATION,
    };
    struct page *new;
    pte_t pte;
    swp_entry_t entry;

    VM_BUG_ON_PAGE(PageTail(page), page);

    /**
     *  遍历页表
     */
    while (page_vma_mapped_walk(&pvmw)) {
        if (PageKsm(page))
            new = page;
        else
            new = page - pvmw.page->index + linear_page_index(vma, pvmw.address);

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
        /* PMD-mapped THP migration entry */
        if (!pvmw.pte) {
            VM_BUG_ON_PAGE(PageHuge(page) || !PageTransCompound(page), page);
            remove_migration_pmd(&pvmw, new);
            continue;
        }
#endif

        get_page(new);

        /**
         *  根据 新页面和 vma 属性生成新的 PTE
         */
        pte = pte_mkold(mk_pte(new, READ_ONCE(vma->vm_page_prot)));
        if (pte_swp_soft_dirty(*pvmw.pte))
            pte = pte_mksoft_dirty(pte);

        /*
		 * Recheck VMA as permissions can change since migration started
		 */
        entry = pte_to_swp_entry(*pvmw.pte);
        if (is_write_migration_entry(entry))
            pte = maybe_mkwrite(pte, vma);
        else if (pte_swp_uffd_wp(*pvmw.pte))
            pte = pte_mkuffd_wp(pte);

        if (unlikely(is_device_private_page(new))) {
            entry = make_device_private_entry(new, pte_write(pte));
            pte = swp_entry_to_pte(entry);
            if (pte_swp_soft_dirty(*pvmw.pte))
                pte = pte_swp_mksoft_dirty(pte);
            if (pte_swp_uffd_wp(*pvmw.pte))
                pte = pte_swp_mkuffd_wp(pte);
        }

#ifdef CONFIG_HUGETLB_PAGE
        if (PageHuge(new)) {
            pte = pte_mkhuge(pte);
            pte = arch_make_huge_pte(pte, vma, new, 0);
            set_huge_pte_at(vma->vm_mm, pvmw.address, pvmw.pte, pte);
            if (PageAnon(new))
                hugepage_add_anon_rmap(new, vma, pvmw.address);
            else
                page_dup_rmap(new, true);
        } else
#endif
        {
            /**
             *  把 新生成的 PTE 的内容写回到 原来映射 的页表(pvmw.pte)中,
             *  完成 PTE 迁移，这样用户进程 地址空间就可以 通过原来的 PTE 访问新页面
             */
            set_pte_at(vma->vm_mm, pvmw.address, pvmw.pte, pte);

            /**
             *  新页面添加到 RMAP 系统
             */
            if (PageAnon(new))
                page_add_anon_rmap(new, vma, pvmw.address, false);
            else
                page_add_file_rmap(new, false);
        }
        if (vma->vm_flags & VM_LOCKED && !PageTransCompound(new))
            mlock_vma_page(new);

        if (PageTransHuge(page) && PageMlocked(page))
            clear_page_mlock(page);

        /* No need to invalidate - it was non-present before */
        update_mmu_cache(vma, pvmw.address, pvmw.pte);
    }

    return true;
}

/*
 * Get rid of all migration entries and replace them by
 * references to the indicated page.
 *
 * 用新page的页表项覆盖迁移页表项
 */
void remove_migration_ptes(struct page *old, struct page *new, bool locked)
{
    /**
     *  
     */
    struct rmap_walk_control rwc = {
        rwc.rmap_one = remove_migration_pte,
        rwc.arg = old,
    };

    /**
     *  walk
     */
    if (locked)
        rmap_walk_locked(new, &rwc);
    else
        rmap_walk(new, &rwc);
}

/*
 * Something used the pte of a page under migration. We need to
 * get to the page and wait until migration is finished.
 * When we return from this function the fault will be retried.
 */
// 当进程访问了正处于迁移过程的页表项的时候，会触发page fault。该函数是这种page fault的主要处理逻辑
// - 将这些进程阻塞，当页面迁移完成，重新唤醒
void __migration_entry_wait(struct mm_struct *mm, pte_t *ptep, spinlock_t *ptl)
{
    pte_t pte;
    swp_entry_t entry;
    struct page *page;

    spin_lock(ptl);
    pte = *ptep;
    if (!is_swap_pte(pte))
        goto out;

    entry = pte_to_swp_entry(pte);
    if (!is_migration_entry(entry))
        goto out;

    page = migration_entry_to_page(entry);

    /*
	 * Once page cache replacement of page migration started, page_count
	 * is zero; but we must not call put_and_wait_on_page_locked() without
	 * a ref. Use get_page_unless_zero(), and just fault again if it fails.
	 */
    if (!get_page_unless_zero(page))
        goto out;
    pte_unmap_unlock(ptep, ptl);
    put_and_wait_on_page_locked(page);
    return;
out:
    pte_unmap_unlock(ptep, ptl);
}

void migration_entry_wait(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
    spinlock_t *ptl = pte_lockptr(mm, pmd);
    pte_t *ptep = pte_offset_map(pmd, address);
    __migration_entry_wait(mm, ptep, ptl);
}

void migration_entry_wait_huge(struct vm_area_struct *vma, struct mm_struct *mm, pte_t *pte)
{
    spinlock_t *ptl = huge_pte_lockptr(hstate_vma(vma), mm, pte);
    __migration_entry_wait(mm, pte, ptl);
}

#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
void pmd_migration_entry_wait(struct mm_struct *mm, pmd_t *pmd)
{
    spinlock_t *ptl;
    struct page *page;

    ptl = pmd_lock(mm, pmd);
    if (!is_pmd_migration_entry(*pmd))
        goto unlock;
    page = migration_entry_to_page(pmd_to_swp_entry(*pmd));
    if (!get_page_unless_zero(page))
        goto unlock;
    spin_unlock(ptl);
    put_and_wait_on_page_locked(page);
    return;
unlock:
    spin_unlock(ptl);
}
#endif

/**
* expected_page_refs - 计算页面的预期引用计数
* @mapping: 指向页面的地址空间的指针
* @page: 指向要计算的页面的指针
*/
static int expected_page_refs(struct address_space *mapping, struct page *page)
{
    /* 基础引用计数为1，表示页面本身的基本引用 */
    int expected_count = 1;

    // 如果页面是设备私有页面，则额外加1
    expected_count += is_device_private_page(page);

    /*
    * 如果页面有mapping，则需要考虑:
    * 1. thp_nr_pages(page): 如果是透明大页，需要计入所有子页面的引用
    * 2. page_has_private(page): 如果页面设置了PG_private，+1
    */
    if (mapping)
        expected_count += thp_nr_pages(page) + page_has_private(page);

    return expected_count;
}
/*
 * Replace the page in the mapping.
 *
 * The number of remaining references must be:
 * 1 for anonymous pages without a mapping
 * 2 for pages with a mapping
 * 3 for pages with a mapping and PagePrivate/PagePrivate2 set.
 *
 * 迁移页面的映射信息到新的页面上,主要就是page结构的一些字段的值
 * 1. 验证和冻结源页面的引用计数
* 2. 将源页面的基本属性(index、mapping等)复制到新页面
* 3. 原子地在radix树中用新页面替换源页面
* 4. 处理页面的脏状态
* 5. 更新内存统计信息
 */
int migrate_page_move_mapping(struct address_space *mapping, struct page *newpage, struct page *page, int extra_count)
{
    XA_STATE(xas, &mapping->i_pages, page_index(page));
    struct zone *oldzone, *newzone;
    int dirty;
    // TODO:
    int expected_count = expected_page_refs(mapping, page) + extra_count;
    int nr = thp_nr_pages(page);

    if (!mapping) {
        /* Anonymous page without mapping */
        if (page_count(page) != expected_count)
            return -EAGAIN;

        /* No turning back from here */
        newpage->index = page->index;
        newpage->mapping = page->mapping;
        if (PageSwapBacked(page))
            __SetPageSwapBacked(newpage);

        return MIGRATEPAGE_SUCCESS;
    }

    oldzone = page_zone(page);
    newzone = page_zone(newpage);

    xas_lock_irq(&xas);
    if (page_count(page) != expected_count || xas_load(&xas) != page) {
        xas_unlock_irq(&xas);
        return -EAGAIN;
    }

    if (!page_ref_freeze(page, expected_count)) {
        xas_unlock_irq(&xas);
        return -EAGAIN;
    }

    /*
	 * Now we know that no one else is looking at the page:
	 * no turning back from here.
	 */
    newpage->index = page->index;
    newpage->mapping = page->mapping;
    page_ref_add(newpage, nr); /* add cache reference */
    if (PageSwapBacked(page)) {
        __SetPageSwapBacked(newpage);
        if (PageSwapCache(page)) {
            SetPageSwapCache(newpage);
            set_page_private(newpage, page_private(page));
        }
    } else {
        VM_BUG_ON_PAGE(PageSwapCache(page), page);
    }

    /* Move dirty while page refs frozen and newpage not yet exposed */
    dirty = PageDirty(page);
    if (dirty) {
        ClearPageDirty(page);
        SetPageDirty(newpage);
    }
    /* 在radix树中替换页面 */
    xas_store(&xas, newpage);
    if (PageTransHuge(page)) {
        int i;

        for (i = 1; i < nr; i++) {
            xas_next(&xas);
            xas_store(&xas, newpage);
        }
    }

    /*
	 * Drop cache reference from old page by unfreezing
	 * to one less reference.
	 * We know this isn't the last reference.
	 */
    page_ref_unfreeze(page, expected_count - nr);

    xas_unlock(&xas);
    /* Leave irq disabled to prevent preemption while updating stats */

    /*
	 * If moved to a different zone then also account
	 * the page for that zone. Other VM counters will be
	 * taken care of when we establish references to the
	 * new page and drop references to the old page.
	 *
	 * Note that anonymous pages are accounted for
	 * via NR_FILE_PAGES and NR_ANON_MAPPED if they
	 * are mapped to swap space.
	 */
    /* 更新内存统计信息 */
    if (newzone != oldzone) {
        struct lruvec *old_lruvec, *new_lruvec;
        struct mem_cgroup *memcg;

        memcg = page_memcg(page);
        old_lruvec = mem_cgroup_lruvec(memcg, oldzone->zone_pgdat);
        new_lruvec = mem_cgroup_lruvec(memcg, newzone->zone_pgdat);

        __mod_lruvec_state(old_lruvec, NR_FILE_PAGES, -nr);
        __mod_lruvec_state(new_lruvec, NR_FILE_PAGES, nr);
        if (PageSwapBacked(page) && !PageSwapCache(page)) {
            __mod_lruvec_state(old_lruvec, NR_SHMEM, -nr);
            __mod_lruvec_state(new_lruvec, NR_SHMEM, nr);
        }
        if (dirty && mapping_can_writeback(mapping)) {
            __mod_lruvec_state(old_lruvec, NR_FILE_DIRTY, -nr);
            __mod_zone_page_state(oldzone, NR_ZONE_WRITE_PENDING, -nr);
            __mod_lruvec_state(new_lruvec, NR_FILE_DIRTY, nr);
            __mod_zone_page_state(newzone, NR_ZONE_WRITE_PENDING, nr);
        }
    }
    local_irq_enable();

    return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(migrate_page_move_mapping);

/*
 * The expected number of remaining references is the same as that
 * of migrate_page_move_mapping().
 */
int migrate_huge_page_move_mapping(struct address_space *mapping, struct page *newpage, struct page *page)
{
    XA_STATE(xas, &mapping->i_pages, page_index(page));
    int expected_count;

    xas_lock_irq(&xas);
    expected_count = 2 + page_has_private(page);
    if (page_count(page) != expected_count || xas_load(&xas) != page) {
        xas_unlock_irq(&xas);
        return -EAGAIN;
    }

    if (!page_ref_freeze(page, expected_count)) {
        xas_unlock_irq(&xas);
        return -EAGAIN;
    }

    newpage->index = page->index;
    newpage->mapping = page->mapping;

    get_page(newpage);

    xas_store(&xas, newpage);

    page_ref_unfreeze(page, expected_count - 1);
}
/*    xle LRU page suitable for pages that do not use PagePrivate/PagePrivate2.
 *
 * Pages are locked upon entry and exit.
 *
  mapping=null的页面会使用这个迁移函数进行迁移
 *
 ** 函数流程
 *
 *  1. 调用 migrate_page_move_mapping
 *  2. 复制 page->index 到新 页面
 *  3. 新页面的 mapping 指向 旧页面 的 mapping
 *  4. 若旧页面 设置了 PG_swapbacked ，新页面也需要设置
 * 
 */
int migrate_page(struct address_space *mapping, struct page *newpage, struct page *page, enum migrate_mode mode)
{
    int rc;

    BUG_ON(PageWriteback(page)); /* Writeback must be complete */

    /**
     *
     */
    rc = migrate_page_move_mapping(mapping, newpage, page, 0);

    if (rc != MIGRATEPAGE_SUCCESS)
        return rc;

    /**
     *
     */
    if (mode != MIGRATE_SYNC_NO_COPY)
        // 拷贝页面内容
        migrate_page_copy(newpage, page);
    else
        // 拷贝剩余的旧page的字段到新page的相应字段中
        migrate_page_states(newpage, page);

    return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(migrate_page);

#ifdef CONFIG_BLOCK
/* Returns true if all buffers are successfully locked */
static bool buffer_migrate_lock_buffers(struct buffer_head *head, enum migrate_mode mode)
{
    struct buffer_head *bh = head;

    /* Simple case, sync compaction */
    if (mode != MIGRATE_ASYNC) {
        do {
            lock_buffer(bh);
            bh = bh->b_this_page;

        } while (bh != head);

        return true;
    }

    /* async case, we cannot block on lock_buffer so use trylock_buffer */
    do {
        if (!trylock_buffer(bh)) {
            /*
			 * We failed to lock the buffer and cannot stall in
			 * async migration. Release the taken locks
			 */
            struct buffer_head *failed_bh = bh;
            bh = head;
            while (bh != failed_bh) {
                unlock_buffer(bh);
                bh = bh->b_this_page;
            }
            return false;
        }

        bh = bh->b_this_page;
    } while (bh != head);
    return true;
}

static int __buffer_migrate_page(struct address_space *mapping, struct page *newpage, struct page *page,
                                 enum migrate_mode mode, bool check_refs)
{
    struct buffer_head *bh, *head;
    int rc;
    int expected_count;

    if (!page_has_buffers(page))
        return migrate_page(mapping, newpage, page, mode);

    /* Check whether page does not have extra refs before we do more work */
    expected_count = expected_page_refs(mapping, page);
    if (page_count(page) != expected_count)
        return -EAGAIN;

    head = page_buffers(page);
    if (!buffer_migrate_lock_buffers(head, mode))
        return -EAGAIN;

    if (check_refs) {
        bool busy;
        bool invalidated = false;

    recheck_buffers:
        busy = false;
        spin_lock(&mapping->private_lock);
        bh = head;
        do {
            if (atomic_read(&bh->b_count)) {
                busy = true;
                break;
            }
            bh = bh->b_this_page;
        } while (bh != head);
        if (busy) {
            if (invalidated) {
                rc = -EAGAIN;
                goto unlock_buffers;
            }
            spin_unlock(&mapping->private_lock);
            invalidate_bh_lrus();
            invalidated = true;
            goto recheck_buffers;
        }
    }

    rc = migrate_page_move_mapping(mapping, newpage, page, 0);
    if (rc != MIGRATEPAGE_SUCCESS)
        goto unlock_buffers;

    attach_page_private(newpage, detach_page_private(page));

    bh = head;
    do {
        set_bh_page(bh, newpage, bh_offset(bh));
        bh = bh->b_this_page;

    } while (bh != head);

    if (mode != MIGRATE_SYNC_NO_COPY)
        migrate_page_copy(newpage, page);
    else
        migrate_page_states(newpage, page);

    rc = MIGRATEPAGE_SUCCESS;
unlock_buffers:
    if (check_refs)
        spin_unlock(&mapping->private_lock);
    bh = head;
    do {
        unlock_buffer(bh);
        bh = bh->b_this_page;

    } while (bh != head);

    return rc;
}

/*
 * Migration function for pages with buffers. This function can only be used
 * if the underlying filesystem guarantees that no other references to "page"
 * exist. For example attached buffer heads are accessed only under page lock.
 */
int buffer_migrate_page(struct address_space *mapping, struct page *newpage, struct page *page, enum migrate_mode mode)
{
    return __buffer_migrate_page(mapping, newpage, page, mode, false);
}
EXPORT_SYMBOL(buffer_migrate_page);

/*
 * Same as above except that this variant is more careful and checks that there
 * are also no buffer head references. This function is the right one for
 * mappings where buffer heads are directly looked up and referenced (such as
 * block device mappings).
 */
int buffer_migrate_page_norefs(struct address_space *mapping, struct page *newpage, struct page *page,
                               enum migrate_mode mode)
{
    return __buffer_migrate_page(mapping, newpage, page, mode, true);
}
#endif

/*
 * Writeback a page to clean the dirty state
 */
static int writeout(struct address_space *mapping, struct page *page)
{
    struct writeback_control wbc = {
        .sync_mode = WB_SYNC_NONE, .nr_to_write = 1, .range_start = 0, .range_end = LLONG_MAX, .for_reclaim = 1
    };
    int rc;

    if (!mapping->a_ops->writepage)
        /* No write method for the address space */
        return -EINVAL;

    if (!clear_page_dirty_for_io(page))
        /* Someone else already triggered a write */
        return -EAGAIN;

    /*
	 * A dirty page may imply that the underlying filesystem has
	 * the page on some queue. So the page must be clean for
	 * migration. Writeout may mean we loose the lock and the
	 * page state is no longer what we checked for earlier.
	 * At this point we know that the migration attempt cannot
	 * be successful.
	 */
    remove_migration_ptes(page, page, false);

    rc = mapping->a_ops->writepage(page, &wbc);

    if (rc != AOP_WRITEPAGE_ACTIVATE)
        /* unlocked. Relock */
        lock_page(page);

    return (rc < 0) ? -EIO : -EAGAIN;
}

/*
 * Default handling if a filesystem does not provide a migration function.
 */
static int fallback_migrate_page(struct address_space *mapping, struct page *newpage, struct page *page,
                                 enum migrate_mode mode)
{
    if (PageDirty(page)) {
        /* Only writeback pages in full synchronous migration */
        switch (mode) {
            case MIGRATE_SYNC:
            case MIGRATE_SYNC_NO_COPY:
                break;
            default:
                return -EBUSY;
        }
        return writeout(mapping, page);
    }

    /*
	 * Buffers may be managed in a filesystem specific way.
	 * We must have no buffers or drop them.
	 */
    if (page_has_private(page) && !try_to_release_page(page, GFP_KERNEL))
        return mode == MIGRATE_SYNC ? -EAGAIN : -EBUSY;

    return migrate_page(mapping, newpage, page, mode);
}

/*
 * Move a page to a newly allocated page
 * The page is locked and all ptes have been successfully removed.
 *
 * The new page will have replaced the old page if this function
 * is successful.
 *
 * Return value:
 *   < 0 - error code
 *  MIGRATEPAGE_SUCCESS - success
 *
 * 进行页面迁移
 */
static int move_to_new_page(struct page *newpage, struct page *page, enum migrate_mode mode)
{
    struct address_space *mapping;
    int rc = -EAGAIN;

    // 这里其实叫做：不是non-lru movable页面比较好
    bool is_lru = !__PageMovable(page);

    VM_BUG_ON_PAGE(!PageLocked(page), page);
    VM_BUG_ON_PAGE(!PageLocked(newpage), newpage);

    mapping = page_mapping(page);

    // LRU页面：
    // 1. 匿名页面
    // 2. 文件映射页面
    if (likely(is_lru)) {
        // 当一个交换页面从交换分区 被读取之后，他会被 添加到 LRU 链表里，我们把它当做一个交换页面缓存，如果此时他还没有设置 RMAP， page->mapping 就为空。
        // 其实这里单独进行判断mapping是必然的。
        // - mapping==null说明反向映射还没设置好，也及时mapping->a_ops的相关字段还没填充，这时候当然不能调用a_ops的migratepage回调函数，因为都没有呀！
        if (!mapping)
            rc = migrate_page(mapping, newpage, page, mode);

        /**
           mapping有值，并且注册了migratepage回调函数，直接用回调函数
         */
        else if (mapping->a_ops->migratepage)
            /*
			 * Most pages have a mapping and most filesystems
			 * provide a migratepage callback. Anonymous pages
			 * are part of swap space which also has its own
			 * migratepage callback. This is the most common path
			 * for page migration.
			 *
			 */
            rc = mapping->a_ops->migratepage(mapping, newpage, page, mode);
        else
            // mapping有值，但是没有注册迁移函数
            // - 匿名页面或者文件系统没有注册回调函数，就使用系统默认的回调函数
            rc = fallback_migrate_page(mapping, newpage, page, mode);
    } else {
        // 非LRU的特殊页面
        /*
		 * In case of non-lru page, it could be released after
		 * isolation step. In that case, we shouldn't try migration.
		 */
        VM_BUG_ON_PAGE(!PageIsolated(page), page);
        // non-lru unmovable page，不可被迁移
        if (!PageMovable(page)) {
            rc = MIGRATEPAGE_SUCCESS;
            __ClearPageIsolated(page);
            goto out;
        }

        // non-lru movable page，直接调用注册的迁移回调函数
        rc = mapping->a_ops->migratepage(mapping, newpage, page, mode);
        WARN_ON_ONCE(rc == MIGRATEPAGE_SUCCESS && !PageIsolated(page));
    }

    /*
	 * When successful, old pagecache page->mapping must be cleared before
	 * page is freed; but stats require that PageAnon be left as PageAnon.
	 */
    if (rc == MIGRATEPAGE_SUCCESS) {
        if (__PageMovable(page)) {
            VM_BUG_ON_PAGE(!PageIsolated(page), page);

            /*
			 * We clear PG_movable under page_lock so any compactor
			 * cannot try to migrate this page.
			 */
            __ClearPageIsolated(page);
        }

        /*
		 * Anonymous and movable page->mapping will be cleared by
		 * free_pages_prepare so don't reset it here for keeping
		 * the type to work PageAnon, for example.
		 */
        // mapping 的低两比特都是0
        if (!PageMappingFlags(page))
            page->mapping = NULL;

        if (likely(!is_zone_device_page(newpage)))
            flush_dcache_page(newpage);
    }
out:
    return rc;
}

/**
 *  尝试迁移 页面到新分配的页面中
 *
 * @page    被迁移的页面
 * @newpage 迁移页面的目的
 * @force   是否强制迁移， migrate_pages() 尝试 2 次以上，force=1
 * @mode    迁移模式
 */
static int __unmap_and_move(struct page *page, struct page *newpage, int force, enum migrate_mode mode)
{
    int rc = -EAGAIN;
    int page_was_mapped = 0;
    struct anon_vma *anon_vma = NULL;

    /**
     *  页面是否属于 非 LRU 页面
     */
    bool is_lru = !__PageMovable(page);

    /**
     *  尝试给页面加锁
     */
    if (!trylock_page(page)) {
        /**
         *  如果加锁不成功，并且 非 强制 迁移 或者迁移模式为异步，
         *  直接退出
         */
        if (!force || mode == MIGRATE_ASYNC)
            goto out;

        /*
		 * It's not safe for direct compaction to call lock_page.
		 * For example, during page readahead pages are added locked
		 * to the LRU. Later, when the IO completes the pages are
		 * marked uptodate and unlocked. However, the queueing
		 * could be merging multiple pages for one bio (e.g.
		 * mpage_readahead). If an allocation happens for the
		 * second or third page, the process can end up locking
		 * the same page twice and deadlocking. Rather than
		 * trying to be clever about what pages can be locked,
		 * avoid the use of lock_page for direct compaction
		 * altogether.
		 *
		 * 当前进程可能处于 直接内存压缩 的内核路径上，通过睡眠 等待页锁是不安全的
		 * 所以直接忽略该页面。
		 */
        if (current->flags & PF_MEMALLOC)
            goto out;

        /**
         *  除了以上情况，否则等待页面被释放
         */
        lock_page(page);
    }

    /**
     *  处理正在回写的页面
     */
    if (PageWriteback(page)) {
        /*
		 * Only in the case of a full synchronous migration is it
		 * necessary to wait for PageWriteback. In the async case,
		 * the retry loop is too short and in the sync-light case,
		 * the overhead of stalling is too much
		 */
        switch (mode) {
                /**
         *  同步迁移
         */
            case MIGRATE_SYNC:
            case MIGRATE_SYNC_NO_COPY:
                break;
            default:
                rc = -EBUSY;
                goto out_unlock;
        }
        if (!force)
            goto out_unlock;

        /**
         *  只有迁移模式为 同步 并且为强制迁移情况，才会等待回写完成
         */
        wait_on_page_writeback(page);
    }

    /*
	 * By try_to_unmap(), page->mapcount goes down to 0 here. In this case,
	 * we cannot notice that anon_vma is freed while we migrates a page.
	 * This get_anon_vma() delays freeing anon_vma pointer until the end
	 * of migration. File cache pages are no problem because of page_lock()
	 * File Caches may use write_page() or lock_page() in migration, then,
	 * just care Anon page here.
	 *
	 * Only page_get_anon_vma() understands the subtleties of
	 * getting a hold on an anon_vma from outside one of its mms.
	 * But if we cannot get anon_vma, then we won't need it anyway,
	 * because that implies that the anon page is no longer mapped
	 * (and cannot be remapped so long as we hold the page lock).
	 *
	 * 处理匿名页面
	 * TODO:
	 */
    if (PageAnon(page) && !PageKsm(page))
        anon_vma = page_get_anon_vma(page);

    /*
	 * Block others from accessing the new page when we get around to
	 * establishing additional references. We are usually the only one
	 * holding a reference to newpage at this point. We used to have a BUG
	 * here if trylock_page(newpage) fails, but would like to allow for
	 * cases where there might be a race with the previous use of newpage.
	 * This is much like races on refcount of oldpage: just don't BUG().
	 *
	 * 尝试 给 即将要被 迁移的目标 页 加锁
	 */
    if (unlikely(!trylock_page(newpage)))
        goto out_unlock;

    /**
     *  若 要迁移的页面不是 LRU页面
     */
    if (unlikely(!is_lru)) {
        /**
         *  迁移页面，并返回
         */
        rc = move_to_new_page(newpage, page, mode);
        goto out_unlock_both;
    }

    // 下面迁移的是LRU页面
    // 1. 交换缓存页面
    // 2. 匿名映射页面
    // 3. 文件映射页面
    /*
	 * Corner case handling:
	 * 1. When a new swap-cache page is read into, it is added to the LRU
	 *      and treated as swapcache but it has no rmap yet.
	 *      Calling try_to_unmap() against a page->mapping==NULL page will
	 *      trigger a BUG.  So handle it here.
	 * 2. An orphaned page (see truncate_complete_page) might have
	 *      fs-private metadata. The page can be picked up due to memory
	 *      offlining.  Everywhere else except page reclaim, the page is
	 *      invisible to the vm, so the page can not be migrated.  So try to
	 *      free the metadata, so the page can be freed.
	 */
    /**
     *  当一个交换页面从交换分区 被读取之后，他会被 添加到 LRU 链表里，我们把它当做一个
     *  交换页面缓存，但是他还没有设置 RMAP，因此 page->mapping 为空。
     *
     *  如果直接 try_to_unmap() 可能导致内核宕机，因此此处特殊处理。
     */
    if (!page->mapping) {
        VM_BUG_ON_PAGE(PageAnon(page), page);
        if (page_has_private(page)) {
            try_to_free_buffers(page);
            goto out_unlock_both;
        }

        /**
     *  判断该页面 的 page->_mapcount 是否 >= 0(是否有映射的用户 PTE)
     */
    } else if (page_mapped(page)) {
        /* Establish migration ptes */
        VM_BUG_ON_PAGE(PageAnon(page) && !PageKsm(page) && !anon_vma, page);

        /**
         *  对于有用户 用户态进程地址空间映射的页面，解除pte映射
         */
        try_to_unmap(page, TTU_MIGRATION | TTU_IGNORE_MLOCK);

        /**
         *  标记页面已经 unmap
         */
        page_was_mapped = 1;
    }

    /**
     *  再次 判断该页面 的 page->_mapcount 是否 < 0(是否没有映射的用户 PTE)
     */
    if (!page_mapped(page))
        /**
         *  如果已经解除 了所有 PTE 的映射，则把 ##他们## 迁移到新的页面
         */
        rc = move_to_new_page(newpage, page, mode);

    if (page_was_mapped)
        // 用新page替换旧page建立新的映射关系
        remove_migration_ptes(page, rc == MIGRATEPAGE_SUCCESS ? newpage : page, false);

out_unlock_both:
    unlock_page(newpage);

out_unlock:
    /* Drop an anon_vma reference if we took one */
    if (anon_vma)
        put_anon_vma(anon_vma);
    unlock_page(page);
out:
    /*
	 * If migration is successful, decrease refcount of the newpage
	 * which will not free the page because new page owner increased
	 * refcounter. As well, if it is LRU page, add the page to LRU
	 * list in here. Use the old state of the isolated source page to
	 * determine if we migrated a LRU page. newpage was already unlocked
	 * and possibly modified by its owner - don't rely on the page
	 * state.
	 */
    /**
     如果迁移成功，减少新页面的引用计数，这不会释放该页面，因为新面的拥有者增加了引用计数
        此外，如果它是LRU页面，则在这里将该页面添加到LRU列表中
    */
    if (rc == MIGRATEPAGE_SUCCESS) {
        if (unlikely(!is_lru))
            /**
             *  不是 LRU 页面，引用计数 -1
             */
            put_page(newpage);
        else
            putback_lru_page(newpage);
    }

    return rc;
}

// 迁移一页
static int unmap_and_move(new_page_t get_new_page, free_page_t put_new_page, unsigned long private, struct page *page,
                          int force, enum migrate_mode mode, enum migrate_reason reason)
{
    // 函数返回值，表示迁移是否成功
    int rc = MIGRATEPAGE_SUCCESS;
    struct page *newpage = NULL;

    /**
	 * 不支持透明大页迁移的系统上,不能迁移透明大页
	 */
    // TODO:这里还会出现是大页的情况吗？大页不是在其他地方被处理了吗？
    // 大页只是被拆分了，但是PG标志还在
    if (!thp_migration_supported() && PageTransHuge(page))
        return -ENOMEM;

    /**
	 * 检查页面引用计数
	 * 引用计数为1说明只剩下页面隔离时获得的引用,
	 * 页面已经没有其他使用者了,可以直接完成迁移。
	 * 清除Active和Unevictable(不可回收）标志,表示页面可以被回收。
	 */
    if (page_count(page) == 1) {
        /* page was freed from under us. So we are done. */

        // 下面按照页面被隔离的情况处理

        ClearPageActive(page);
        ClearPageUnevictable(page);
        // unlikely 只是内核提供给编译器的一些提示信息，用于知道编译器进行代码优化，并不会影响if语句本身的语义
        // 是non-lru页面，接下来要进一步判断是不是movable页面
        if (unlikely(__PageMovable(page))) {
            lock_page(page);
            // 不是non-lru movable page
            // PageMovable()检查页面是否真的是可移动页面
            // 返回false表示不是可移动页面了,可能情况:
            // 1. 驱动已经将页面标记为不可移动
            // 2. 页面正在被迁移
            // 3. 页面的address_space已改变
            if (!PageMovable(page))
                // 如果不是可移动页面,但又设置了isolated标志
                // 说明这个页面曾经被隔离过但状态已改变
                // 需要清除isolated标志使其回到正常状态
                // PG_isolated用于标记页面当前已被隔离,不能被其他路径使用
                /* 如果页面状态已改变为不可移动,但还保留着isolated标志 */
                /* 这会导致页面处于"被隔离但又不可移动"的矛盾状态 */
                /* 清除isolated标志让页面回到正常状态,可以被内存管理系统正常使用 */
                __ClearPageIsolated(page);
            unlock_page(page);
        }
        goto out;
    }

    /**
	 * 分配一个新的页面
	 * 失败则返回-ENOMEM
	 */
    newpage = get_new_page(page, private);
    if (!newpage)
        return -ENOMEM;

    /**
	 * 尝试迁移页面到新分配的页面中
	 */
    rc = __unmap_and_move(page, newpage, force, mode);

    /**
	 * 迁移成功则更新页面迁移原因
	 */
    if (rc == MIGRATEPAGE_SUCCESS)
        set_page_owner_migrate_reason(newpage, reason);

out:
    /**
	 * 若返回值不是-EAGAIN说明迁移完成(成功或失败)
	 * 需要从LRU链表中删除该页面,并更新统计计数
	 */
    if (rc != -EAGAIN) {
        list_del(&page->lru);

        /*
		 * 非__PageMovable的页面需要更新node统计信息
		 */
        if (likely(!__PageMovable(page)))
            mod_node_page_state(page_pgdat(page), NR_ISOLATED_ANON + page_is_file_lru(page), -thp_nr_pages(page));
    }

    /**
	 * 根据迁移结果做最终处理:
	 * 1. 迁移成功:释放源页面的引用计数(除了内存故障的场景)
	 * 2. 迁移失败:
	 *    - 不可重试则恢复页面到原来的位置
	 *    - 释放新分配的页面
	 */
    if (rc == MIGRATEPAGE_SUCCESS) {
        if (reason != MR_MEMORY_FAILURE) {
            put_page(page);
        }
    } else {
        if (rc != -EAGAIN) {
            if (likely(!__PageMovable(page))) {
                putback_lru_page(page);
                goto put_new;
            }

            lock_page(page);
            if (PageMovable(page))
                putback_movable_page(page);
            else
                __ClearPageIsolated(page);
            unlock_page(page);
            put_page(page);
        }
    put_new:
        if (put_new_page)
            put_new_page(newpage, private);
        else
            put_page(newpage);
    }

    return rc;
}

/*
 * Counterpart of unmap_and_move_page() for hugepage migration.
 *
 * This function doesn't wait the completion of hugepage I/O
 * because there is no race between I/O and migration for hugepage.
 * Note that currently hugepage I/O occurs only in direct I/O
 * where no lock is held and PG_writeback is irrelevant,
 * and writeback status of all subpages are counted in the reference
 * count of the head page (i.e. if all subpages of a 2MB hugepage are
 * under direct I/O, the reference of the head page is 512 and a bit more.)
 * This means that when we try to migrate hugepage whose subpages are
 * doing direct I/O, some references remain after try_to_unmap() and
 * hugepage migration fails without data corruption.
 *
 * There is also no race when direct I/O is issued on the page under migration,
 * because then pte is replaced with migration swap entry and direct I/O code
 * will wait in the page fault for migration to complete.
 */
/*                                                                                    │
  * NOTE: 这里提到直接IO，是指通过文件映射方式创建的HugeTLB大页需要使用的，而不是用于普通的文件映射的IO。HugeTLB大页不能用于普通的文件映射
  *
  * 这是用于hugetlb大页迁移的 unmap_and_move_page() 的对应函数。                                │
  *                                                                                      │
  * 这个函数不等待大页 I/O 的完成，因为在大页的迁移过程中没有 I/O 和迁移之间的竞争。     │
  *
  * 目前大页 I/O 仅发生在直接 I/O 中，此时没有持有锁，PG_writeback标志无关紧要， 所有子页面的写回状态都计入到头页面的引用计数中（即如果一个 2MB的大页的所有子页面都在进行直接 I/O，则头页面的引用计数为 512 及以上│
  *
  * 这意味着当我们尝试迁移正在进行直接 I/O 的大页时，try_to_unmap()                      │
 之后仍然会有一些引用存在,大页迁移会失败，但不会导致数据损坏。                                               │
  *                                                                                      │
  * 当在迁移中的页面上发起直接 I/O 时，也没有竞争情况，因为此时 PTE                      │
 被替换为迁移交换条目，                                                                  │
  * 而直接 I/O 代码会在页面故障时等待迁移完成。                                          │
 * @get_new_page: 分配目标大页的函数
 * @put_new_page: 迁移失败时释放目标大页的函数
 * @private: 传递给get_new_page()的私有数据
 * @hpage: 要迁移的大页
 * @force: 是否在迁移期间强制进行内存压缩
 * @mode: 迁移模式(异步、同步或无复制同步)
 * @reason: 页面迁移的原因
 *
 * 成功返回0,失败返回错误码
 */
static int unmap_and_move_huge_page(new_page_t get_new_page, free_page_t put_new_page, unsigned long private,
                                    struct page *hpage, int force, enum migrate_mode mode, int reason)
{
    pg_data_t *pgdat = NODE_DATA(node);
    int isolated;
    struct page *new_hpage;
    struct anon_vma *anon_vma = NULL;
    struct address_space *mapping = NULL;

    /* 检查架构和大页大小是否支持迁移 */
    if (!hugepage_migration_supported(page_hstate(hpage))) {
        putback_active_hugepage(hpage);
        return -ENOSYS;
    }

    /* 分配新的大页 */
    new_hpage = get_new_page(hpage, private);
    if (!new_hpage)
        return -ENOMEM;

    // PG_locked
    if (!trylock_page(hpage)) {
        // lock page失败
        /* 如果不是强制迁移则直接返回 */
        if (!force)
            goto out;
        /* 非同步模式下直接返回 */
        switch (mode) {
            case MIGRATE_SYNC:
            case MIGRATE_SYNC_NO_COPY:
                break;
            default:
                goto out;
        }
        /* 强制获取页面锁 */
        lock_page(hpage);
    }

    // TODO
    // page->private!=null && mapping==null
    if (page_private(hpage) && !page_mapping(hpage)) {
        rc = -EBUSY;
        goto out_unlock;
    }

    /* 如果是匿名页,获取anon_vma */
    // 通过MAP_HUGTLB|MAP_ANOMOUS 申请的是匿名页
    // 通过hugetlbfs申请的是文件映射页
    if (PageAnon(hpage))
        anon_vma = page_get_anon_vma(hpage);

    /* 尝试锁定目标大页 */
    if (unlikely(!trylock_page(new_hpage)))
        goto put_anon;

    // 如果当前大页还在被用户程序的页表映射，需要先解除映射
    if (page_mapped(hpage)) {
        bool mapping_locked = false;
        enum ttu_flags ttu = TTU_MIGRATION | TTU_IGNORE_MLOCK;

        // 使用文件映射方式申请的大页
        if (!PageAnon(hpage)) {
            mapping = hugetlb_page_mapping_lock_write(hpage);
            if (unlikely(!mapping))
                goto unlock_put_anon;

            mapping_locked = true;
            ttu |= TTU_RMAP_LOCKED;
        }

        /* 解除页表映射 */
        try_to_unmap(hpage, ttu);
        page_was_mapped = 1;

        if (mapping_locked)
            i_mmap_unlock_write(mapping);
    }

    /* 如果页面已经解除映射,执行实际迁移 */
    if (!page_mapped(hpage))
        rc = move_to_new_page(new_hpage, hpage, mode);

    /* 如果页面之前有映射,需要移除迁移页表项 */
    if (page_was_mapped)
        remove_migration_ptes(hpage, rc == MIGRATEPAGE_SUCCESS ? new_hpage : hpage, false);

unlock_put_anon:
    /* 解锁新页面 */
    unlock_page(new_hpage);

put_anon:
    /* 如果有anon_vma引用,释放它 */
    if (anon_vma)
        put_anon_vma(anon_vma);

    /* 迁移成功则更新hugepage状态 */
    if (rc == MIGRATEPAGE_SUCCESS) {
        move_hugetlb_state(hpage, new_hpage, reason);
        put_new_page = NULL;
    }

out_unlock:
    /* 解锁源页面 */
    unlock_page(hpage);
out:
    /* 如果不需要重试,将源页面放回活动列表 */
    if (rc != -EAGAIN)
        putback_active_hugepage(hpage);

    /*
     * 如果迁移失败且有释放回调函数,则使用它。
     * 否则,put_page()会释放隔离期间获得的引用。
     */
    if (put_new_page)
        put_new_page(new_hpage, private);
    else
        putback_active_hugepage(new_hpage);

    return rc;
}

/*
 * migrate_pages - migrate the pages specified in a list, to the free pages
 *		   supplied as the target for the page migration
 *
 * @from:		The list of pages to be migrated.
 *              将要迁移的页面列表
 *
 * @get_new_page:	The function used to allocate free pages to be used
 *			    as the target of the page migration.
 *              申请新内存的页面的函数指针
 *
 * @put_new_page:	The function used to free target pages if migration
 *			    fails, or NULL if no special handling is necessary.
 *              迁移失败时释放目标页面的函数指针
 *
 * @private:		Private data to be passed on to get_new_page()
 *
 * @mode:		The migration mode that specifies the constraints for
 *			    page migration, if any.
 *              迁移模式
 *
 * @reason:		The reason for page migration. 迁移原因
 *
 * The function returns after 10 attempts or if no pages are movable any more
 * because the list has become empty or no retryable pages exist any more.
 * The caller should call putback_movable_pages() to return pages to the LRU
 * or free list only if ret != 0.
 *
 * Returns the number of pages that were not migrated, or an error code.
 *
 * 页面迁移 核心函数
 *
 * 迁移一个进程的所有页面到制定内存节点上。
 *
 *  起初，页面迁移是为了适配 NUMA 架构，
 *  现在，页面迁移也可以用于 内存规整，内存热插拔等。
 *
 * 注意此接口 和 系统调用接口区分
 * ---------------------------------------------------------------------
 * long migrate_pages(int pid, unsigned long maxnode,
 *                        const unsigned long *old_nodes,
 *                        const unsigned long *new_nodes);
 */
/**
 * migrate_pages - 页面迁移的核心实现函数
 * @from: 待迁移页面的源链表头
 *      - 链表中的每个页面都必须已经从原来的管理系统中隔离出来(isolated)
 * @get_new_page: 获取迁移目标页面的回调函数
 *      - 函数原型: struct page* (*new_page_t)(struct page *page, unsigned long private)
 *      - 为每个源页面分配对应的目标页面
 *      - 通常会考虑NUMA节点亲和性来选择合适的目标位置
 * @put_new_page: 释放目标页面的回调函数(迁移失败时调用)
 *      - 函数原型: void (*free_page_t)(struct page *page, unsigned long private) 
 *      - 负责清理迁移失败时已分配的目标页面
 *      - 如果为NULL,则使用默认的释放函数
 * @private: 传递给回调函数的私有数据
 *      - 用于回调函数的额外参数传递
 *      - 典型用途是传递迁移策略、NUMA信息等
 * @mode: 迁移模式标志位
 *      MIGRATE_ASYNC: 异步迁移模式
 *          - 不等待迁移完成就返回
 *          - 允许部分页面迁移失败
 *          - 适用于内存规整等非关键场景
 *      MIGRATE_SYNC: 同步迁移模式  
 *          - 等待所有迁移操作完成
 *          - 会重试失败的页面迁移
 *          - 用于内存热插拔等需要确保迁移成功的场景
 *      MIGRATE_SYNC_NO_COPY: 同步模式但不复制页面内容
 *          - 只更新页面映射关系
 *          - 用于已知页面内容可丢弃的场景
 * @reason: 迁移原因,用于跟踪和调试
 *      MR_COMPACTION: 内存规整触发的迁移
 *      MR_MEMORY_HOTPLUG: 内存热插拔触发的迁移
 *      MR_MEMORY_FAILURE: 内存错误恢复触发的迁移
 *      MR_SYSCALL: 系统调用触发的迁移
 *      MR_NUMA: NUMA优化触发的迁移
 *      
 * 函数执行流程:
 * 1. 遍历待迁移页面链表
 *    - 每次取出一个页面进行处理
 *    - 透明大页(THP)会作为一个整体迁移。啥意思？透明大页不是整体被先拆分成了很多的标准4kB页面了吗？这些所有的4KB页面一起整体迁移？
 *    - 允许通过信号中断长时间的迁移
 *
 * 2. 对每个页面执行迁移:
 *    - 调用get_new_page获取目标页面
 *    - 建立临时的迁移页表项(migration entry)
 *    - 复制页面内容(除MIGRATE_SYNC_NO_COPY外)
 *    - 更新页面相关的各类计数器和标志位
 *    - 处理页面的引用计数和映射关系
 *
 * 3. 特殊情况处理:
 *    - 设备专用内存页面需要特殊迁移流程
 *    - 被锁定的页面会推迟迁移
 *    - 正在回写的页面需要等待IO完成
 *    - 大页面的迁移需要额外的同步机制
 *
 * 4. 错误恢复:
 *    - 迁移失败时回滚已完成的更改
 *    - 清理临时的迁移页表项
 *    - 恢复页面的原始状态
 *    - 释放已分配的目标页面
 * 
 * 5. 完成后的清理工作:
 *    - 更新各类统计计数
 *    - 触发相关的内存规整操作
 *    - 唤醒等待迁移完成的进程
 *
 * 注意事项:
 * - 调用者必须确保源页面已经被正确隔离
 * - 迁移过程中不能持有页面锁,以避免死锁
 * - 透明大页的迁移可能会被拆分处理
 * - 需要考虑并发和同步问题
 * - 某些页面可能无法迁移(如内核代码页)
 *
 * 返回值:
 * 0        - 所有页面都成功迁移
 * 正数 N   - N个页面迁移失败 
 * -ENOMEM  - 无法分配新页面
 * -EAGAIN  - 暂时无法完成迁移,可重试
 * -EEXIST  - 页面已经在迁移中
 * -EINTR   - 被信号中断
 *
 * 上下文:
 * - 可以在进程上下文或软中断上下文中调用
 * - 不能在中断上下文或持有自旋锁时调用
 * - 调用时最好不要禁止内存回收
 */
/* 内存页面迁移主函数 */
int migrate_pages(struct list_head *from, /* 待迁移页面链表头 */
                  new_page_t get_new_page, /* 分配新页面回调函数 */
                  free_page_t put_new_page, /* 释放新页面回调函数 */
                  unsigned long private, /* 传递给回调函数的私有数据 */
                  enum migrate_mode mode, /* 迁移模式:同步/异步 */
                  int reason) /* 迁移原因,用于debug */
{
    // retry用于控制普通页面的迁移重试
    int retry = 1;

    // thp_retry用于控制透明大页(THP)的迁移重试
    int thp_retry = 1;

    // nr_failed统计迁移失败的普通页面数量
    int nr_failed = 0;

    // nr_succeeded统计迁移成功的普通页面数量
    int nr_succeeded = 0;

    // nr_thp_succeeded统计迁移成功的透明大页数量
    int nr_thp_succeeded = 0;

    // nr_thp_failed统计迁移失败的透明大页数量
    int nr_thp_failed = 0;

    // nr_thp_split统计需要拆分的透明大页数量
    int nr_thp_split = 0;

    // pass记录当前是第几轮迁移尝试
    int pass = 0;

    // is_thp标记当前是否是hugetlb 或者透明大页
    bool is_thp = false;

    // page/page2为遍历链表使用的指针
    struct page *page;
    struct page *page2;

    // 判断当前进程是否有写入交换区的权限
    // TODO
    int swapwrite = current->flags & PF_SWAPWRITE;

    // rc用于保存函数返回值,nr_subpages记录页面的子页数量
    int rc, nr_subpages;

    // TODO: 这里没搞懂
    // 如果进程未设置swap标志位,则临时设置它
    // 在页面进行迁移的时候，有些页面可能需要被写回到交换区?比如呢？
    if (!swapwrite)
        current->flags |= PF_SWAPWRITE;

    // 最多尝试迁移10轮,只要还有页面需要重试就继续
    for (pass = 0; pass < 10 && (retry || thp_retry); pass++) {
        // 重置重试标志
        retry = 0;
        thp_retry = 0;

        // 下面是为什么&page->lru != from 可以用来表示有没有到末尾的原理解释：
        /*
        * Linux双向循环链表的定义:
        * 1. 链表头 list_head 初始化时指向自己:
        *    - next 指向自己的地址
        *    - prev 也指向自己的地址
        *
        * 示意图:
        *  list_head(from)
        *     |
        *     v
        *   +----------+
        *   |    *next-|--> 指向自己
        *   |    *prev-|--> 指向自己
        *   +----------+
        */
        /*
        * 当添加节点时:
        * 1. 第一个节点:next/prev 都指向链表头
        * 2. 后续节点:依次连接,最后一个节点的next指向链表头
        *
        * 示意图:
        * +-----------+     +-----------+     +-----------+
        * |list_head  |     |  page1    |     |  page2    |
        * |  (from)   |<--->|   lru     |<--->|   lru     |
        * +-----------+     +-----------+     +-----------+
        *      ^                                    |
        *      +------------------------------------+
        *           最后一个节点next指向链表头
        *
        * 链表为空时,from->next = from->prev = from(自己)
            有节点时,最后一个节点的next指向链表头from
            因此遍历时检查 &page->lru != from:

            不等于from,说明还没到尾部
            等于from,说明已经遍历完所有节点回到链表头
        */

        // 遍历待迁移页面链表
        /*
        * list_for_each_entry_safe 在这里展开后等价于:
        * for (page = list_first_entry(from, struct page, lru);  // 获取第一个页面
        *      &page->lru != (from) &&                           // 未到链表尾
        *      ({ page2 = list_next_entry(page, lru); 1; });    // 保存下一个页面
        *      page = page2)                                     // 移动到下一个页面
        *
        * 其中:
        * - page 是 struct page 类型,当前遍历到的页面
        * - page2 是 struct page 类型,下一个要遍历的页面.
        *   - page2 = list_next_entry(page, lru) 提前保存下一个页面
        *   - 这样即使当前页面被删除也不会影响遍历
        * - from 是链表头
        * - lru 是 struct page 一个字段的名称.在这里应该是就是作为一个通用的list
        */
        // 遍历待迁移链表
        // page：当前节点
        // page2：下一个节点
        list_for_each_entry_safe(page, page2, from, lru)
        {
        retry:
            // 但是在内存软下线的情况下，似乎只有hugetlb会走到这一步吧；透明大页已经被分割了？
            // 是的，透明大页被切割为普通页面的时候，PG_head、PG_compound标志都被清空了。这里应该是对应其他情况吧
            // TODO:既然是这样，这里为啥要用PageTransHuge而不是PageHuge？
            // 是否是透明大页
            is_thp = PageTransHuge(page) && !PageHuge(page);
            nr_subpages = thp_nr_pages(page);

            // 定期让出CPU,防止长时间占用
            cond_resched();

            // 处理hugetlb迁移
            if (PageHuge(page))
                rc = unmap_and_move_huge_page(get_new_page, put_new_page, private, page, pass > 2, mode, reason);
            // 处理普通页面迁移
            else
                rc = unmap_and_move(get_new_page, put_new_page, private, page, pass > 2, mode, reason);

            // 根据迁移结果进行相应处理
            switch (rc) {
                case -ENOMEM:
                    // 处理内存不足的情况
                    if (is_thp) {
                        // 尝试拆分透明大页后重试
                        lock_page(page);
                        rc = split_huge_page_to_list(page, from);
                        unlock_page(page);
                        if (!rc) {
                            // 拆分成功,重新处理当前页面
                            list_safe_reset_next(page, page2, lru);
                            nr_thp_split++;
                            goto retry;
                        }
                        // 拆分失败记录统计信息
                        nr_thp_failed++;
                        nr_failed += nr_subpages;
                        goto out;
                    }
                    // 普通页面内存不足,直接记录失败
                    nr_failed++;
                    goto out;

                case -EAGAIN:
                    // 需要重试的情况
                    if (is_thp) {
                        // 透明大页标记重试
                        thp_retry++;
                        break;
                    }
                    // 普通页面标记重试
                    retry++;
                    break;

                case MIGRATEPAGE_SUCCESS:
                    // 迁移成功的情况
                    if (is_thp) {
                        // 统计透明大页成功数
                        nr_thp_succeeded++;
                        nr_succeeded += nr_subpages;
                        break;
                    }
                    // 统计普通页面成功数
                    nr_succeeded++;
                    break;

                default:
                    // 其他错误情况(EBUSY,ENOSYS等)
                    if (is_thp) {
                        // 统计透明大页失败数
                        nr_thp_failed++;
                        nr_failed += nr_subpages;
                        break;
                    }
                    // 统计普通页面失败数
                    nr_failed++;
                    break;
            }
        }
    }

    // 累加最终的失败页面数
    nr_failed += retry + thp_retry;
    nr_thp_failed += thp_retry;
    rc = nr_failed;

out:
    // 更新全局的页面迁移统计信息
    count_vm_events(PGMIGRATE_SUCCESS, nr_succeeded);
    count_vm_events(PGMIGRATE_FAIL, nr_failed);
    count_vm_events(THP_MIGRATION_SUCCESS, nr_thp_succeeded);
    count_vm_events(THP_MIGRATION_FAIL, nr_thp_failed);
    count_vm_events(THP_MIGRATION_SPLIT, nr_thp_split);

    // 记录迁移跟踪信息用于调试
    trace_mm_migrate_pages(nr_succeeded, nr_failed, nr_thp_succeeded, nr_thp_failed, nr_thp_split, mode, reason);

    // 恢复进程的原始swap标志位
    if (!swapwrite)
        current->flags &= ~PF_SWAPWRITE;

    // 返回失败页面数作为结果
    return rc;
}

/*
 * alloc_migration_target - 为源页面分配新的目标页面
 * @page: 需要迁移的源页面
 * @private: 包含迁移控制参数的私有数据
 *
 * 该函数为页面迁移分配目标页面。它处理不同类型页面的分配:
 * - 普通页面: 在指定节点上分配相同大小的页面
 * - 大页(HugePage): 分配同样大小的大页 
 * - 透明大页(THP): 分配THP大小的页面
 * 
 * 分配过程中会考虑:
 * - 源页面所在的内存区域(ZONE)
 * - NUMA节点亲和性 
 * - 页面迁移约束(GFP掩码)
 * 
 * 返回值:
 * - 成功时返回新分配的页面指针
 * - 失败时返回NULL
 */
struct page *alloc_migration_target(struct page *page, unsigned long private)
{
    struct migration_target_control *mtc;
    gfp_t gfp_mask;
    unsigned int order = 0;
    struct page *new_page = NULL;
    int nid;
    int zidx;

    // 获取迁移控制参数
    mtc = (struct migration_target_control *)private;
    gfp_mask = mtc->gfp_mask;
    nid = mtc->nid;
    // 如果未指定目标节点,使用源页面所在节点
    if (nid == NUMA_NO_NODE)
        nid = page_to_nid(page);

    // 处理大页(HugePage)的分配
    if (PageHuge(page)) {
        struct hstate *h = page_hstate(compound_head(page));

        gfp_mask = htlb_modify_alloc_mask(h, gfp_mask);
        return alloc_huge_page_nodemask(h, nid, mtc->nmask, gfp_mask);
    }

    // 处理透明大页(THP)的分配
    if (PageTransHuge(page)) {
        /*
         * 清除__GFP_RECLAIM标志以保持与普通THP分配一致,
         * 因为THP分配通常不允许回收
         */
        gfp_mask &= ~__GFP_RECLAIM;
        gfp_mask |= GFP_TRANSHUGE;
        order = HPAGE_PMD_ORDER;
    }

    // 根据源页面所在zone设置适当的GFP掩码
    zidx = zone_idx(page_zone(page));
    if (is_highmem_idx(zidx) || zidx == ZONE_MOVABLE)
        gfp_mask |= __GFP_HIGHMEM;

    // 分配新页面
    new_page = __alloc_pages_nodemask(gfp_mask, order, nid, mtc->nmask);

    // 能走到这里，肯定是透明大页
    // 如果分配的是THP,进行必要的初始化
    if (new_page && PageTransHuge(new_page))
        prep_transhuge_page(new_page);

    return new_page;
}

#ifdef CONFIG_NUMA

static int store_status(int __user *status, int start, int value, int nr)
{
    while (nr-- > 0) {
        if (put_user(value, status + start))
            return -EFAULT;
        start++;
    }

    return 0;
}

static int do_move_pages_to_node(struct mm_struct *mm, struct list_head *pagelist, int node)
{
    int err;
    struct migration_target_control mtc = {
        .nid = node,
        .gfp_mask = GFP_HIGHUSER_MOVABLE | __GFP_THISNODE,
    };

    err = migrate_pages(pagelist, alloc_migration_target, NULL, (unsigned long)&mtc, MIGRATE_SYNC, MR_SYSCALL);
    if (err)
        putback_movable_pages(pagelist);
    return err;
}

/*
 * Resolves the given address to a struct page, isolates it from the LRU and
 * puts it to the given pagelist.
 * Returns:
 *     errno - if the page cannot be found/isolated
 *     0 - when it doesn't have to be migrated because it is already on the
 *         target node
 *     1 - when it has been queued
 */
static int add_page_for_migration(struct mm_struct *mm, unsigned long addr, int node, struct list_head *pagelist,
                                  bool migrate_all)
{
    struct vm_area_struct *vma;
    struct page *page;
    unsigned int follflags;
    int err;

    mmap_read_lock(mm);
    err = -EFAULT;
    vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start || !vma_migratable(vma))
        goto out;

    /* FOLL_DUMP to ignore special (like zero) pages */
    follflags = FOLL_GET | FOLL_DUMP;
    page = follow_page(vma, addr, follflags);

    err = PTR_ERR(page);
    if (IS_ERR(page))
        goto out;

    err = -ENOENT;
    if (!page)
        goto out;

    err = 0;
    if (page_to_nid(page) == node)
        goto out_putpage;

    err = -EACCES;
    if (page_mapcount(page) > 1 && !migrate_all)
        goto out_putpage;

    if (PageHuge(page)) {
        if (PageHead(page)) {
            isolate_huge_page(page, pagelist);
            err = 1;
        }
    } else {
        struct page *head;

        head = compound_head(page);
        err = isolate_lru_page(head);
        if (err)
            goto out_putpage;

        err = 1;
        list_add_tail(&head->lru, pagelist);
        mod_node_page_state(page_pgdat(head), NR_ISOLATED_ANON + page_is_file_lru(head), thp_nr_pages(head));
    }
out_putpage:
    /*
	 * Either remove the duplicate refcount from
	 * isolate_lru_page() or drop the page ref if it was
	 * not isolated.
	 */
    put_page(page);
out:
    mmap_read_unlock(mm);
    return err;
}

static int move_pages_and_store_status(struct mm_struct *mm, int node, struct list_head *pagelist, int __user *status,
                                       int start, int i, unsigned long nr_pages)
{
    int err;

    if (list_empty(pagelist))
        return 0;

    err = do_move_pages_to_node(mm, pagelist, node);
    if (err) {
        /*
		 * Positive err means the number of failed
		 * pages to migrate.  Since we are going to
		 * abort and return the number of non-migrated
		 * pages, so need to incude the rest of the
		 * nr_pages that have not been attempted as
		 * well.
		 */
        if (err > 0)
            err += nr_pages - i - 1;
        return err;
    }
    return store_status(status, start, node, i - start);
}

/*
 * Migrate an array of page address onto an array of nodes and fill
 * the corresponding array of status.
 */
static int do_pages_move(struct mm_struct *mm, nodemask_t task_nodes, unsigned long nr_pages,
                         const void __user *__user *pages, const int __user *nodes, int __user *status, int flags)
{
    int current_node = NUMA_NO_NODE;
    LIST_HEAD(pagelist);
    int start, i;
    int err = 0, err1;

    migrate_prep();

    for (i = start = 0; i < nr_pages; i++) {
        const void __user *p;
        unsigned long addr;
        int node;

        err = -EFAULT;
        if (get_user(p, pages + i))
            goto out_flush;
        if (get_user(node, nodes + i))
            goto out_flush;
        addr = (unsigned long)untagged_addr(p);

        err = -ENODEV;
        if (node < 0 || node >= MAX_NUMNODES)
            goto out_flush;
        if (!node_state(node, N_MEMORY))
            goto out_flush;

        err = -EACCES;
        if (!node_isset(node, task_nodes))
            goto out_flush;

        if (current_node == NUMA_NO_NODE) {
            current_node = node;
            start = i;
        } else if (node != current_node) {
            err = move_pages_and_store_status(mm, current_node, &pagelist, status, start, i, nr_pages);
            if (err)
                goto out;
            start = i;
            current_node = node;
        }

        /*
		 * Errors in the page lookup or isolation are not fatal and we simply
		 * report them via status
		 */
        err = add_page_for_migration(mm, addr, current_node, &pagelist, flags & MPOL_MF_MOVE_ALL);

        if (err > 0) {
            /* The page is successfully queued for migration */
            continue;
        }

        /*
		 * If the page is already on the target node (!err), store the
		 * node, otherwise, store the err.
		 */
        err = store_status(status, i, err ?: current_node, 1);
        if (err)
            goto out_flush;

        err = move_pages_and_store_status(mm, current_node, &pagelist, status, start, i, nr_pages);
        if (err)
            goto out;
        current_node = NUMA_NO_NODE;
    }
out_flush:
    /* Make sure we do not overwrite the existing error */
    err1 = move_pages_and_store_status(mm, current_node, &pagelist, status, start, i, nr_pages);
    if (err >= 0)
        err = err1;
out:
    return err;
}

/*
 * Determine the nodes of an array of pages and store it in an array of status.
 */
static void do_pages_stat_array(struct mm_struct *mm, unsigned long nr_pages, const void __user **pages, int *status)
{
    unsigned long i;

    mmap_read_lock(mm);

    for (i = 0; i < nr_pages; i++) {
        unsigned long addr = (unsigned long)(*pages);
        struct vm_area_struct *vma;
        struct page *page;
        int err = -EFAULT;

        vma = find_vma(mm, addr);
        if (!vma || addr < vma->vm_start)
            goto set_status;

        /* FOLL_DUMP to ignore special (like zero) pages */
        page = follow_page(vma, addr, FOLL_DUMP);

        err = PTR_ERR(page);
        if (IS_ERR(page))
            goto set_status;

        err = page ? page_to_nid(page) : -ENOENT;
    set_status:
        *status = err;

        pages++;
        status++;
    }

    mmap_read_unlock(mm);
}

/*
 * Determine the nodes of a user array of pages and store it in
 * a user array of status.
 */
static int do_pages_stat(struct mm_struct *mm, unsigned long nr_pages, const void __user *__user *pages,
                         int __user *status)
{
#define DO_PAGES_STAT_CHUNK_NR 16
    const void __user *chunk_pages[DO_PAGES_STAT_CHUNK_NR];
    int chunk_status[DO_PAGES_STAT_CHUNK_NR];

    while (nr_pages) {
        unsigned long chunk_nr;

        chunk_nr = nr_pages;
        if (chunk_nr > DO_PAGES_STAT_CHUNK_NR)
            chunk_nr = DO_PAGES_STAT_CHUNK_NR;

        if (copy_from_user(chunk_pages, pages, chunk_nr * sizeof(*chunk_pages)))
            break;

        do_pages_stat_array(mm, chunk_nr, chunk_pages, chunk_status);

        if (copy_to_user(status, chunk_status, chunk_nr * sizeof(*status)))
            break;

        pages += chunk_nr;
        status += chunk_nr;
        nr_pages -= chunk_nr;
    }
    return nr_pages ? -EFAULT : 0;
}

static struct mm_struct *find_mm_struct(pid_t pid, nodemask_t *mem_nodes)
{
    struct task_struct *task;
    struct mm_struct *mm;

    /*
	 * There is no need to check if current process has the right to modify
	 * the specified process when they are same.
	 */
    if (!pid) {
        mmget(current->mm);
        *mem_nodes = cpuset_mems_allowed(current);
        return current->mm;
    }

    /* Find the mm_struct */
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return ERR_PTR(-ESRCH);
    }
    get_task_struct(task);

    /*
	 * Check if this process has the right to modify the specified
	 * process. Use the regular "ptrace_may_access()" checks.
	 */
    if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
        rcu_read_unlock();
        mm = ERR_PTR(-EPERM);
        goto out;
    }
    rcu_read_unlock();

    mm = ERR_PTR(security_task_movememory(task));
    if (IS_ERR(mm))
        goto out;
    *mem_nodes = cpuset_mems_allowed(task);
    mm = get_task_mm(task);
out:
    put_task_struct(task);
    if (!mm)
        mm = ERR_PTR(-EINVAL);
    return mm;
}

/*
 * Move a list of pages in the address space of the currently executing
 * process.
 */
static int kernel_move_pages(pid_t pid, unsigned long nr_pages, const void __user *__user *pages,
                             const int __user *nodes, int __user *status, int flags)
{
    struct mm_struct *mm;
    int err;
    nodemask_t task_nodes;

    /* Check flags */
    if (flags & ~(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL))
        return -EINVAL;

    if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE))
        return -EPERM;

    mm = find_mm_struct(pid, &task_nodes);
    if (IS_ERR(mm))
        return PTR_ERR(mm);

    if (nodes)
        err = do_pages_move(mm, task_nodes, nr_pages, pages, nodes, status, flags);
    else
        err = do_pages_stat(mm, nr_pages, pages, status);

    mmput(mm);
    return err;
}

SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages, const void __user *__user *, pages, const int __user *,
                nodes, int __user *, status, int, flags)
{
    return kernel_move_pages(pid, nr_pages, pages, nodes, status, flags);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE6(move_pages, pid_t, pid, compat_ulong_t, nr_pages, compat_uptr_t __user *, pages32,
                       const int __user *, nodes, int __user *, status, int, flags)
{
    const void __user *__user *pages;
    int i;

    pages = compat_alloc_user_space(nr_pages * sizeof(void *));
    for (i = 0; i < nr_pages; i++) {
        compat_uptr_t p;

        if (get_user(p, pages32 + i) || put_user(compat_ptr(p), pages + i))
            return -EFAULT;
    }
    return kernel_move_pages(pid, nr_pages, pages, nodes, status, flags);
}
#endif /* CONFIG_COMPAT */

#ifdef CONFIG_NUMA_BALANCING
/*
 * Returns true if this is a safe migration target node for misplaced NUMA
 * pages. Currently it only checks the watermarks which crude
 */
static bool migrate_balanced_pgdat(struct pglist_data *pgdat, unsigned long nr_migrate_pages)
{
    int z;

    /**
     *  遍历 node 中zone
     */
    for (z = pgdat->nr_zones - 1; z >= 0; z--) {
        struct zone *zone = pgdat->node_zones + z;

        if (!populated_zone(zone))
            continue;

        /* Avoid waking kswapd by allocating pages_to_migrate pages. */
        if (!zone_watermark_ok(zone, 0, high_wmark_pages(zone) + nr_migrate_pages, ZONE_MOVABLE, 0))
            continue;
        return true;
    }
    return false;
}

static struct page *alloc_misplaced_dst_page(struct page *page, unsigned long data)
{
    int nid = (int)data;
    struct page *newpage;

    newpage = __alloc_pages_node(
            nid,
            (GFP_HIGHUSER_MOVABLE | __GFP_THISNODE | __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN) & ~__GFP_RECLAIM,
            0);

    return newpage;
}

static int numamigrate_isolate_page(pg_data_t *pgdat, struct page *page)
{
    int page_lru;

    VM_BUG_ON_PAGE(compound_order(page) && !PageTransHuge(page), page);

    /* Avoid migrating to a node that is nearly full */
    if (!migrate_balanced_pgdat(pgdat, compound_nr(page)))
        return 0;

    if (isolate_lru_page(page))
        return 0;

    /*
	 * migrate_misplaced_transhuge_page() skips page migration's usual
	 * check on page_count(), so we must do it here, now that the page
	 * has been isolated: a GUP pin, or any other pin, prevents migration.
	 * The expected page count is 3: 1 for page's mapcount and 1 for the
	 * caller's pin and 1 for the reference taken by isolate_lru_page().
	 */
    if (PageTransHuge(page) && page_count(page) != 3) {
        putback_lru_page(page);
        return 0;
    }

    page_lru = page_is_file_lru(page);
    mod_node_page_state(page_pgdat(page), NR_ISOLATED_ANON + page_lru, thp_nr_pages(page));

    /*
	 * Isolating the page has taken another reference, so the
	 * caller's reference can be safely dropped without the page
	 * disappearing underneath us during migration.
	 */
    put_page(page);
    return 1;
}

bool pmd_trans_migrating(pmd_t pmd)
{
    struct page *page = pmd_page(pmd);
    return PageLocked(page);
}

/*
 * Attempt to migrate a misplaced page to the specified destination
 * node. Caller is expected to have an elevated reference count on
 * the page that will be dropped by this function before returning.
 */
int migrate_misplaced_page(struct page *page, struct vm_area_struct *vma, int node)
{
    pg_data_t *pgdat = NODE_DATA(node);
    int isolated;
    int nr_remaining;
    LIST_HEAD(migratepages);

    /*
	 * Don't migrate file pages that are mapped in multiple processes
	 * with execute permissions as they are probably shared libraries.
	 */
    if (page_mapcount(page) != 1 && page_is_file_lru(page) && (vma->vm_flags & VM_EXEC))
        goto out;

    /*
	 * Also do not migrate dirty pages as not all filesystems can move
	 * dirty pages in MIGRATE_ASYNC mode which is a waste of cycles.
	 */
    if (page_is_file_lru(page) && PageDirty(page))
        goto out;

    isolated = numamigrate_isolate_page(pgdat, page);
    if (!isolated)
        goto out;

    list_add(&page->lru, &migratepages);
    nr_remaining = migrate_pages(&migratepages, alloc_misplaced_dst_page, NULL, node, MIGRATE_ASYNC, MR_NUMA_MISPLACED);
    if (nr_remaining) {
        if (!list_empty(&migratepages)) {
            list_del(&page->lru);
            dec_node_page_state(page, NR_ISOLATED_ANON + page_is_file_lru(page));
            putback_lru_page(page);
        }
        isolated = 0;
    } else
        count_vm_numa_event(NUMA_PAGE_MIGRATE);
    BUG_ON(!list_empty(&migratepages));
    return isolated;

out:
    put_page(page);
    return 0;
}
#endif /* CONFIG_NUMA_BALANCING */

#if defined(CONFIG_NUMA_BALANCING) && defined(CONFIG_TRANSPARENT_HUGEPAGE)
/*
 * Migrates a THP to a given target node. page must be locked and is unlocked
 * before returning.
 */
int migrate_misplaced_transhuge_page(struct mm_struct *mm, struct vm_area_struct *vma, pmd_t *pmd, pmd_t entry,
                                     unsigned long address, struct page *page, int node)
{
    spinlock_t *ptl;
    pg_data_t *pgdat = NODE_DATA(node);
    int isolated = 0;
    struct page *new_page = NULL;
    int page_lru = page_is_file_lru(page);
    unsigned long start = address & HPAGE_PMD_MASK;

    new_page = alloc_pages_node(node, (GFP_TRANSHUGE_LIGHT | __GFP_THISNODE), HPAGE_PMD_ORDER);
    if (!new_page)
        goto out_fail;
    prep_transhuge_page(new_page);

    isolated = numamigrate_isolate_page(pgdat, page);
    if (!isolated) {
        put_page(new_page);
        goto out_fail;
    }

    /* Prepare a page as a migration target */
    __SetPageLocked(new_page);
    if (PageSwapBacked(page))
        __SetPageSwapBacked(new_page);

    /* anon mapping, we can simply copy page->mapping to the new page: */
    new_page->mapping = page->mapping;
    new_page->index = page->index;
    /* flush the cache before copying using the kernel virtual address */
    flush_cache_range(vma, start, start + HPAGE_PMD_SIZE);
    migrate_page_copy(new_page, page);
    WARN_ON(PageLRU(new_page));

    /* Recheck the target PMD */
    ptl = pmd_lock(mm, pmd);
    if (unlikely(!pmd_same(*pmd, entry) || !page_ref_freeze(page, 2))) {
        spin_unlock(ptl);

        /* Reverse changes made by migrate_page_copy() */
        if (TestClearPageActive(new_page))
            SetPageActive(page);
        if (TestClearPageUnevictable(new_page))
            SetPageUnevictable(page);

        unlock_page(new_page);
        put_page(new_page); /* Free it */

        /* Retake the callers reference and putback on LRU */
        get_page(page);
        putback_lru_page(page);
        mod_node_page_state(page_pgdat(page), NR_ISOLATED_ANON + page_lru, -HPAGE_PMD_NR);

        goto out_unlock;
    }

    entry = mk_huge_pmd(new_page, vma->vm_page_prot);
    entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);

    /*
	 * Overwrite the old entry under pagetable lock and establish
	 * the new PTE. Any parallel GUP will either observe the old
	 * page blocking on the page lock, block on the page table
	 * lock or observe the new page. The SetPageUptodate on the
	 * new page and page_add_new_anon_rmap guarantee the copy is
	 * visible before the pagetable update.
	 */
    page_add_anon_rmap(new_page, vma, start, true);
    /*
	 * At this point the pmd is numa/protnone (i.e. non present) and the TLB
	 * has already been flushed globally.  So no TLB can be currently
	 * caching this non present pmd mapping.  There's no need to clear the
	 * pmd before doing set_pmd_at(), nor to flush the TLB after
	 * set_pmd_at().  Clearing the pmd here would introduce a race
	 * condition against MADV_DONTNEED, because MADV_DONTNEED only holds the
	 * mmap_lock for reading.  If the pmd is set to NULL at any given time,
	 * MADV_DONTNEED won't wait on the pmd lock and it'll skip clearing this
	 * pmd.
	 */
    set_pmd_at(mm, start, pmd, entry);
    update_mmu_cache_pmd(vma, address, &entry);

    page_ref_unfreeze(page, 2);
    mlock_migrate_page(new_page, page);
    page_remove_rmap(page, true);
    set_page_owner_migrate_reason(new_page, MR_NUMA_MISPLACED);

    spin_unlock(ptl);

    /* Take an "isolate" reference and put new page on the LRU. */
    get_page(new_page);
    putback_lru_page(new_page);

    unlock_page(new_page);
    unlock_page(page);
    put_page(page); /* Drop the rmap reference */
    put_page(page); /* Drop the LRU isolation reference */

    count_vm_events(PGMIGRATE_SUCCESS, HPAGE_PMD_NR);
    count_vm_numa_events(NUMA_PAGE_MIGRATE, HPAGE_PMD_NR);

    mod_node_page_state(page_pgdat(page), NR_ISOLATED_ANON + page_lru, -HPAGE_PMD_NR);
    return isolated;

out_fail:
    count_vm_events(PGMIGRATE_FAIL, HPAGE_PMD_NR);
    ptl = pmd_lock(mm, pmd);
    if (pmd_same(*pmd, entry)) {
        entry = pmd_modify(entry, vma->vm_page_prot);
        set_pmd_at(mm, start, pmd, entry);
        update_mmu_cache_pmd(vma, address, &entry);
    }
    spin_unlock(ptl);

out_unlock:
    unlock_page(page);
    put_page(page);
    return 0;
}
#endif /* CONFIG_NUMA_BALANCING */

#endif /* CONFIG_NUMA */

#ifdef CONFIG_DEVICE_PRIVATE
static int migrate_vma_collect_hole(unsigned long start, unsigned long end, __always_unused int depth,
                                    struct mm_walk *walk)
{
    struct migrate_vma *migrate = walk->private;
    unsigned long addr;

    /* Only allow populating anonymous memory. */
    if (!vma_is_anonymous(walk->vma)) {
        for (addr = start; addr < end; addr += PAGE_SIZE) {
            migrate->src[migrate->npages] = 0;
            migrate->dst[migrate->npages] = 0;
            migrate->npages++;
        }
        return 0;
    }

    for (addr = start; addr < end; addr += PAGE_SIZE) {
        migrate->src[migrate->npages] = MIGRATE_PFN_MIGRATE;
        migrate->dst[migrate->npages] = 0;
        migrate->npages++;
        migrate->cpages++;
    }

    return 0;
}

static int migrate_vma_collect_skip(unsigned long start, unsigned long end, struct mm_walk *walk)
{
    struct migrate_vma *migrate = walk->private;
    unsigned long addr;

    for (addr = start; addr < end; addr += PAGE_SIZE) {
        migrate->dst[migrate->npages] = 0;
        migrate->src[migrate->npages++] = 0;
    }

    return 0;
}

static int migrate_vma_collect_pmd(pmd_t *pmdp, unsigned long start, unsigned long end, struct mm_walk *walk)
{
    struct migrate_vma *migrate = walk->private;
    struct vm_area_struct *vma = walk->vma;
    struct mm_struct *mm = vma->vm_mm;
    unsigned long addr = start, unmapped = 0;
    spinlock_t *ptl;
    pte_t *ptep;

again:
    if (pmd_none(*pmdp))
        return migrate_vma_collect_hole(start, end, -1, walk);

    if (pmd_trans_huge(*pmdp)) {
        struct page *page;

        ptl = pmd_lock(mm, pmdp);
        if (unlikely(!pmd_trans_huge(*pmdp))) {
            spin_unlock(ptl);
            goto again;
        }

        page = pmd_page(*pmdp);
        if (is_huge_zero_page(page)) {
            spin_unlock(ptl);
            split_huge_pmd(vma, pmdp, addr);
            if (pmd_trans_unstable(pmdp))
                return migrate_vma_collect_skip(start, end, walk);
        } else {
            int ret;

            get_page(page);
            spin_unlock(ptl);
            if (unlikely(!trylock_page(page)))
                return migrate_vma_collect_skip(start, end, walk);
            ret = split_huge_page(page);
            unlock_page(page);
            put_page(page);
            if (ret)
                return migrate_vma_collect_skip(start, end, walk);
            if (pmd_none(*pmdp))
                return migrate_vma_collect_hole(start, end, -1, walk);
        }
    }

    if (unlikely(pmd_bad(*pmdp)))
        return migrate_vma_collect_skip(start, end, walk);

    ptep = pte_offset_map_lock(mm, pmdp, addr, &ptl);
    arch_enter_lazy_mmu_mode();

    for (; addr < end; addr += PAGE_SIZE, ptep++) {
        unsigned long mpfn = 0, pfn;
        struct page *page;
        swp_entry_t entry;
        pte_t pte;

        pte = *ptep;

        if (pte_none(pte)) {
            if (vma_is_anonymous(vma)) {
                mpfn = MIGRATE_PFN_MIGRATE;
                migrate->cpages++;
            }
            goto next;
        }

        if (!pte_present(pte)) {
            /*
			 * Only care about unaddressable device page special
			 * page table entry. Other special swap entries are not
			 * migratable, and we ignore regular swapped page.
			 */
            entry = pte_to_swp_entry(pte);
            if (!is_device_private_entry(entry))
                goto next;

            page = device_private_entry_to_page(entry);
            if (!(migrate->flags & MIGRATE_VMA_SELECT_DEVICE_PRIVATE) || page->pgmap->owner != migrate->pgmap_owner)
                goto next;

            mpfn = migrate_pfn(page_to_pfn(page)) | MIGRATE_PFN_MIGRATE;
            if (is_write_device_private_entry(entry))
                mpfn |= MIGRATE_PFN_WRITE;
        } else {
            if (!(migrate->flags & MIGRATE_VMA_SELECT_SYSTEM))
                goto next;
            pfn = pte_pfn(pte);
            if (is_zero_pfn(pfn)) {
                mpfn = MIGRATE_PFN_MIGRATE;
                migrate->cpages++;
                goto next;
            }
            page = vm_normal_page(migrate->vma, addr, pte);
            mpfn = migrate_pfn(pfn) | MIGRATE_PFN_MIGRATE;
            mpfn |= pte_write(pte) ? MIGRATE_PFN_WRITE : 0;
        }

        /* FIXME support THP */
        if (!page || !page->mapping || PageTransCompound(page)) {
            mpfn = 0;
            goto next;
        }

        /*
		 * By getting a reference on the page we pin it and that blocks
		 * any kind of migration. Side effect is that it "freezes" the
		 * pte.
		 *
		 * We drop this reference after isolating the page from the lru
		 * for non device page (device page are not on the lru and thus
		 * can't be dropped from it).
		 */
        get_page(page);
        migrate->cpages++;

        /*
		 * Optimize for the common case where page is only mapped once
		 * in one process. If we can lock the page, then we can safely
		 * set up a special migration page table entry now.
		 */
        if (trylock_page(page)) {
            pte_t swp_pte;

            mpfn |= MIGRATE_PFN_LOCKED;
            ptep_get_and_clear(mm, addr, ptep);

            /* Setup special migration page table entry */
            entry = make_migration_entry(page, mpfn & MIGRATE_PFN_WRITE);
            swp_pte = swp_entry_to_pte(entry);
            if (pte_present(pte)) {
                if (pte_soft_dirty(pte))
                    swp_pte = pte_swp_mksoft_dirty(swp_pte);
                if (pte_uffd_wp(pte))
                    swp_pte = pte_swp_mkuffd_wp(swp_pte);
            } else {
                if (pte_swp_soft_dirty(pte))
                    swp_pte = pte_swp_mksoft_dirty(swp_pte);
                if (pte_swp_uffd_wp(pte))
                    swp_pte = pte_swp_mkuffd_wp(swp_pte);
            }
            set_pte_at(mm, addr, ptep, swp_pte);

            /*
			 * This is like regular unmap: we remove the rmap and
			 * drop page refcount. Page won't be freed, as we took
			 * a reference just above.
			 */
            page_remove_rmap(page, false);
            put_page(page);

            if (pte_present(pte))
                unmapped++;
        }

    next:
        migrate->dst[migrate->npages] = 0;
        migrate->src[migrate->npages++] = mpfn;
    }
    arch_leave_lazy_mmu_mode();
    pte_unmap_unlock(ptep - 1, ptl);

    /* Only flush the TLB if we actually modified any entries */
    if (unmapped)
        flush_tlb_range(walk->vma, start, end);

    return 0;
}

static const struct mm_walk_ops migrate_vma_walk_ops = {
    .pmd_entry = migrate_vma_collect_pmd,
    .pte_hole = migrate_vma_collect_hole,
};

/*
 * migrate_vma_collect() - collect pages over a range of virtual addresses
 * @migrate: migrate struct containing all migration information
 *
 * This will walk the CPU page table. For each virtual address backed by a
 * valid page, it updates the src array and takes a reference on the page, in
 * order to pin the page until we lock it and unmap it.
 */
static void migrate_vma_collect(struct migrate_vma *migrate)
{
    struct mmu_notifier_range range;

    /*
	 * Note that the pgmap_owner is passed to the mmu notifier callback so
	 * that the registered device driver can skip invalidating device
	 * private page mappings that won't be migrated.
	 */
    mmu_notifier_range_init_migrate(&range, 0, migrate->vma, migrate->vma->vm_mm, migrate->start, migrate->end,
                                    migrate->pgmap_owner);
    mmu_notifier_invalidate_range_start(&range);

    walk_page_range(migrate->vma->vm_mm, migrate->start, migrate->end, &migrate_vma_walk_ops, migrate);

    mmu_notifier_invalidate_range_end(&range);
    migrate->end = migrate->start + (migrate->npages << PAGE_SHIFT);
}

/*
 * migrate_vma_check_page() - check if page is pinned or not
 * @page: struct page to check
 *
 * Pinned pages cannot be migrated. This is the same test as in
 * migrate_page_move_mapping(), except that here we allow migration of a
 * ZONE_DEVICE page.
 */
static bool migrate_vma_check_page(struct page *page)
{
    /*
	 * One extra ref because caller holds an extra reference, either from
	 * isolate_lru_page() for a regular page, or migrate_vma_collect() for
	 * a device page.
	 */
    int extra = 1;

    /*
	 * FIXME support THP (transparent huge page), it is bit more complex to
	 * check them than regular pages, because they can be mapped with a pmd
	 * or with a pte (split pte mapping).
	 */
    if (PageCompound(page))
        return false;

    /* Page from ZONE_DEVICE have one extra reference */
    if (is_zone_device_page(page)) {
        /*
		 * Private page can never be pin as they have no valid pte and
		 * GUP will fail for those. Yet if there is a pending migration
		 * a thread might try to wait on the pte migration entry and
		 * will bump the page reference count. Sadly there is no way to
		 * differentiate a regular pin from migration wait. Hence to
		 * avoid 2 racing thread trying to migrate back to CPU to enter
		 * infinite loop (one stoping migration because the other is
		 * waiting on pte migration entry). We always return true here.
		 *
		 * FIXME proper solution is to rework migration_entry_wait() so
		 * it does not need to take a reference on page.
		 */
        return is_device_private_page(page);
    }

    /* For file back page */
    if (page_mapping(page))
        extra += 1 + page_has_private(page);

    if ((page_count(page) - extra) > page_mapcount(page))
        return false;

    return true;
}

/*
 * migrate_vma_prepare() - lock pages and isolate them from the lru
 * @migrate: migrate struct containing all migration information
 *
 * This locks pages that have been collected by migrate_vma_collect(). Once each
 * page is locked it is isolated from the lru (for non-device pages). Finally,
 * the ref taken by migrate_vma_collect() is dropped, as locked pages cannot be
 * migrated by concurrent kernel threads.
 */
static void migrate_vma_prepare(struct migrate_vma *migrate)
{
    const unsigned long npages = migrate->npages;
    const unsigned long start = migrate->start;
    unsigned long addr, i, restore = 0;
    bool allow_drain = true;

    lru_add_drain();

    for (i = 0; (i < npages) && migrate->cpages; i++) {
        struct page *page = migrate_pfn_to_page(migrate->src[i]);
        bool remap = true;

        if (!page)
            continue;

        if (!(migrate->src[i] & MIGRATE_PFN_LOCKED)) {
            /*
			 * Because we are migrating several pages there can be
			 * a deadlock between 2 concurrent migration where each
			 * are waiting on each other page lock.
			 *
			 * Make migrate_vma() a best effort thing and backoff
			 * for any page we can not lock right away.
			 */
            if (!trylock_page(page)) {
                migrate->src[i] = 0;
                migrate->cpages--;
                put_page(page);
                continue;
            }
            remap = false;
            migrate->src[i] |= MIGRATE_PFN_LOCKED;
        }

        /* ZONE_DEVICE pages are not on LRU */
        if (!is_zone_device_page(page)) {
            if (!PageLRU(page) && allow_drain) {
                /* Drain CPU's pagevec */
                lru_add_drain_all();
                allow_drain = false;
            }

            if (isolate_lru_page(page)) {
                if (remap) {
                    migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
                    migrate->cpages--;
                    restore++;
                } else {
                    migrate->src[i] = 0;
                    unlock_page(page);
                    migrate->cpages--;
                    put_page(page);
                }
                continue;
            }

            /* Drop the reference we took in collect */
            put_page(page);
        }

        if (!migrate_vma_check_page(page)) {
            if (remap) {
                migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
                migrate->cpages--;
                restore++;

                if (!is_zone_device_page(page)) {
                    get_page(page);
                    putback_lru_page(page);
                }
            } else {
                migrate->src[i] = 0;
                unlock_page(page);
                migrate->cpages--;

                if (!is_zone_device_page(page))
                    putback_lru_page(page);
                else
                    put_page(page);
            }
        }
    }

    for (i = 0, addr = start; i < npages && restore; i++, addr += PAGE_SIZE) {
        struct page *page = migrate_pfn_to_page(migrate->src[i]);

        if (!page || (migrate->src[i] & MIGRATE_PFN_MIGRATE))
            continue;

        remove_migration_pte(page, migrate->vma, addr, page);

        migrate->src[i] = 0;
        unlock_page(page);
        put_page(page);
        restore--;
    }
}

/*
 * migrate_vma_unmap() - replace page mapping with special migration pte entry
 * @migrate: migrate struct containing all migration information
 *
 * Replace page mapping (CPU page table pte) with a special migration pte entry
 * and check again if it has been pinned. Pinned pages are restored because we
 * cannot migrate them.
 *
 * This is the last step before we call the device driver callback to allocate
 * destination memory and copy contents of original page over to new page.
 */
static void migrate_vma_unmap(struct migrate_vma *migrate)
{
    int flags = TTU_MIGRATION | TTU_IGNORE_MLOCK;
    const unsigned long npages = migrate->npages;
    const unsigned long start = migrate->start;
    unsigned long addr, i, restore = 0;

    for (i = 0; i < npages; i++) {
        struct page *page = migrate_pfn_to_page(migrate->src[i]);

        if (!page || !(migrate->src[i] & MIGRATE_PFN_MIGRATE))
            continue;

        if (page_mapped(page)) {
            try_to_unmap(page, flags);
            if (page_mapped(page))
                goto restore;
        }

        if (migrate_vma_check_page(page))
            continue;

    restore:
        migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
        migrate->cpages--;
        restore++;
    }

    for (addr = start, i = 0; i < npages && restore; addr += PAGE_SIZE, i++) {
        struct page *page = migrate_pfn_to_page(migrate->src[i]);

        if (!page || (migrate->src[i] & MIGRATE_PFN_MIGRATE))
            continue;

        remove_migration_ptes(page, page, false);

        migrate->src[i] = 0;
        unlock_page(page);
        restore--;

        if (is_zone_device_page(page))
            put_page(page);
        else
            putback_lru_page(page);
    }
}

/**
 * migrate_vma_setup() - prepare to migrate a range of memory
 * @args: contains the vma, start, and pfns arrays for the migration
 *
 * Returns: negative errno on failures, 0 when 0 or more pages were migrated
 * without an error.
 *
 * Prepare to migrate a range of memory virtual address range by collecting all
 * the pages backing each virtual address in the range, saving them inside the
 * src array.  Then lock those pages and unmap them. Once the pages are locked
 * and unmapped, check whether each page is pinned or not.  Pages that aren't
 * pinned have the MIGRATE_PFN_MIGRATE flag set (by this function) in the
 * corresponding src array entry.  Then restores any pages that are pinned, by
 * remapping and unlocking those pages.
 *
 * The caller should then allocate destination memory and copy source memory to
 * it for all those entries (ie with MIGRATE_PFN_VALID and MIGRATE_PFN_MIGRATE
 * flag set).  Once these are allocated and copied, the caller must update each
 * corresponding entry in the dst array with the pfn value of the destination
 * page and with the MIGRATE_PFN_VALID and MIGRATE_PFN_LOCKED flags set
 * (destination pages must have their struct pages locked, via lock_page()).
 *
 * Note that the caller does not have to migrate all the pages that are marked
 * with MIGRATE_PFN_MIGRATE flag in src array unless this is a migration from
 * device memory to system memory.  If the caller cannot migrate a device page
 * back to system memory, then it must return VM_FAULT_SIGBUS, which has severe
 * consequences for the userspace process, so it must be avoided if at all
 * possible.
 *
 * For empty entries inside CPU page table (pte_none() or pmd_none() is true) we
 * do set MIGRATE_PFN_MIGRATE flag inside the corresponding source array thus
 * allowing the caller to allocate device memory for those unback virtual
 * address.  For this the caller simply has to allocate device memory and
 * properly set the destination entry like for regular migration.  Note that
 * this can still fails and thus inside the device driver must check if the
 * migration was successful for those entries after calling migrate_vma_pages()
 * just like for regular migration.
 *
 * After that, the callers must call migrate_vma_pages() to go over each entry
 * in the src array that has the MIGRATE_PFN_VALID and MIGRATE_PFN_MIGRATE flag
 * set. If the corresponding entry in dst array has MIGRATE_PFN_VALID flag set,
 * then migrate_vma_pages() to migrate struct page information from the source
 * struct page to the destination struct page.  If it fails to migrate the
 * struct page information, then it clears the MIGRATE_PFN_MIGRATE flag in the
 * src array.
 *
 * At this point all successfully migrated pages have an entry in the src
 * array with MIGRATE_PFN_VALID and MIGRATE_PFN_MIGRATE flag set and the dst
 * array entry with MIGRATE_PFN_VALID flag set.
 *
 * Once migrate_vma_pages() returns the caller may inspect which pages were
 * successfully migrated, and which were not.  Successfully migrated pages will
 * have the MIGRATE_PFN_MIGRATE flag set for their src array entry.
 *
 * It is safe to update device page table after migrate_vma_pages() because
 * both destination and source page are still locked, and the mmap_lock is held
 * in read mode (hence no one can unmap the range being migrated).
 *
 * Once the caller is done cleaning up things and updating its page table (if it
 * chose to do so, this is not an obligation) it finally calls
 * migrate_vma_finalize() to update the CPU page table to point to new pages
 * for successfully migrated pages or otherwise restore the CPU page table to
 * point to the original source pages.
 */
int migrate_vma_setup(struct migrate_vma *args)
{
    long nr_pages = (args->end - args->start) >> PAGE_SHIFT;

    args->start &= PAGE_MASK;
    args->end &= PAGE_MASK;
    if (!args->vma || is_vm_hugetlb_page(args->vma) || (args->vma->vm_flags & VM_SPECIAL) || vma_is_dax(args->vma))
        return -EINVAL;
    if (nr_pages <= 0)
        return -EINVAL;
    if (args->start < args->vma->vm_start || args->start >= args->vma->vm_end)
        return -EINVAL;
    if (args->end <= args->vma->vm_start || args->end > args->vma->vm_end)
        return -EINVAL;
    if (!args->src || !args->dst)
        return -EINVAL;

    memset(args->src, 0, sizeof(*args->src) * nr_pages);
    args->cpages = 0;
    args->npages = 0;

    migrate_vma_collect(args);

    if (args->cpages)
        migrate_vma_prepare(args);
    if (args->cpages)
        migrate_vma_unmap(args);

    /*
	 * At this point pages are locked and unmapped, and thus they have
	 * stable content and can safely be copied to destination memory that
	 * is allocated by the drivers.
	 */
    return 0;
}
EXPORT_SYMBOL(migrate_vma_setup);

/*
 * This code closely matches the code in:
 *   __handle_mm_fault()
 *     handle_pte_fault()
 *       do_anonymous_page()
 * to map in an anonymous zero page but the struct page will be a ZONE_DEVICE
 * private page.
 */
static void migrate_vma_insert_page(struct migrate_vma *migrate, unsigned long addr, struct page *page,
                                    unsigned long *src, unsigned long *dst)
{
    struct vm_area_struct *vma = migrate->vma;
    struct mm_struct *mm = vma->vm_mm;
    bool flush = false;
    spinlock_t *ptl;
    pte_t entry;
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;

    /* Only allow populating anonymous memory */
    if (!vma_is_anonymous(vma))
        goto abort;

    pgdp = pgd_offset(mm, addr);
    p4dp = p4d_alloc(mm, pgdp, addr);
    if (!p4dp)
        goto abort;
    pudp = pud_alloc(mm, p4dp, addr);
    if (!pudp)
        goto abort;
    pmdp = pmd_alloc(mm, pudp, addr);
    if (!pmdp)
        goto abort;

    if (pmd_trans_huge(*pmdp) || pmd_devmap(*pmdp))
        goto abort;

    /*
	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under mmap_write_lock(mm) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have mmap_read_lock(mm).
	 */
    if (pte_alloc(mm, pmdp))
        goto abort;

    /* See the comment in pte_alloc_one_map() */
    if (unlikely(pmd_trans_unstable(pmdp)))
        goto abort;

    if (unlikely(anon_vma_prepare(vma)))
        goto abort;
    if (mem_cgroup_charge(page, vma->vm_mm, GFP_KERNEL))
        goto abort;

    /*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
    __SetPageUptodate(page);

    if (is_zone_device_page(page)) {
        if (is_device_private_page(page)) {
            swp_entry_t swp_entry;

            swp_entry = make_device_private_entry(page, vma->vm_flags & VM_WRITE);
            entry = swp_entry_to_pte(swp_entry);
        }
    } else {
        entry = mk_pte(page, vma->vm_page_prot);
        if (vma->vm_flags & VM_WRITE)
            entry = pte_mkwrite(pte_mkdirty(entry));
    }

    ptep = pte_offset_map_lock(mm, pmdp, addr, &ptl);

    if (check_stable_address_space(mm))
        goto unlock_abort;

    if (pte_present(*ptep)) {
        unsigned long pfn = pte_pfn(*ptep);

        if (!is_zero_pfn(pfn))
            goto unlock_abort;
        flush = true;
    } else if (!pte_none(*ptep))
        goto unlock_abort;

    /*
	 * Check for userfaultfd but do not deliver the fault. Instead,
	 * just back off.
	 */
    if (userfaultfd_missing(vma))
        goto unlock_abort;

    inc_mm_counter(mm, MM_ANONPAGES);
    page_add_new_anon_rmap(page, vma, addr, false);
    if (!is_zone_device_page(page))
        lru_cache_add_inactive_or_unevictable(page, vma);
    get_page(page);

    if (flush) {
        flush_cache_page(vma, addr, pte_pfn(*ptep));
        ptep_clear_flush_notify(vma, addr, ptep);
        set_pte_at_notify(mm, addr, ptep, entry);
        update_mmu_cache(vma, addr, ptep);
    } else {
        /* No need to invalidate - it was non-present before */
        set_pte_at(mm, addr, ptep, entry);
        update_mmu_cache(vma, addr, ptep);
    }

    pte_unmap_unlock(ptep, ptl);
    *src = MIGRATE_PFN_MIGRATE;
    return;

unlock_abort:
    pte_unmap_unlock(ptep, ptl);
abort:
    *src &= ~MIGRATE_PFN_MIGRATE;
}

/**
 * migrate_vma_pages() - migrate meta-data from src page to dst page
 * @migrate: migrate struct containing all migration information
 *
 * This migrates struct page meta-data from source struct page to destination
 * struct page. This effectively finishes the migration from source page to the
 * destination page.
 */
void migrate_vma_pages(struct migrate_vma *migrate)
{
    const unsigned long npages = migrate->npages;
    const unsigned long start = migrate->start;
    struct mmu_notifier_range range;
    unsigned long addr, i;
    bool notified = false;

    for (i = 0, addr = start; i < npages; addr += PAGE_SIZE, i++) {
        struct page *newpage = migrate_pfn_to_page(migrate->dst[i]);
        struct page *page = migrate_pfn_to_page(migrate->src[i]);
        struct address_space *mapping;
        int r;

        if (!newpage) {
            migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
            continue;
        }

        if (!page) {
            if (!(migrate->src[i] & MIGRATE_PFN_MIGRATE))
                continue;
            if (!notified) {
                notified = true;

                mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, NULL, migrate->vma->vm_mm, addr, migrate->end);
                mmu_notifier_invalidate_range_start(&range);
            }
            migrate_vma_insert_page(migrate, addr, newpage, &migrate->src[i], &migrate->dst[i]);
            continue;
        }

        mapping = page_mapping(page);

        if (is_zone_device_page(newpage)) {
            if (is_device_private_page(newpage)) {
                /*
				 * For now only support private anonymous when
				 * migrating to un-addressable device memory.
				 */
                if (mapping) {
                    migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
                    continue;
                }
            } else {
                /*
				 * Other types of ZONE_DEVICE page are not
				 * supported.
				 */
                migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
                continue;
            }
        }

        r = migrate_page(mapping, newpage, page, MIGRATE_SYNC_NO_COPY);
        if (r != MIGRATEPAGE_SUCCESS)
            migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
    }

    /*
	 * No need to double call mmu_notifier->invalidate_range() callback as
	 * the above ptep_clear_flush_notify() inside migrate_vma_insert_page()
	 * did already call it.
	 */
    if (notified)
        mmu_notifier_invalidate_range_only_end(&range);
}
EXPORT_SYMBOL(migrate_vma_pages);

/**
 * migrate_vma_finalize() - restore CPU page table entry
 * @migrate: migrate struct containing all migration information
 *
 * This replaces the special migration pte entry with either a mapping to the
 * new page if migration was successful for that page, or to the original page
 * otherwise.
 *
 * This also unlocks the pages and puts them back on the lru, or drops the extra
 * refcount, for device pages.
 */
void migrate_vma_finalize(struct migrate_vma *migrate)
{
    const unsigned long npages = migrate->npages;
    unsigned long i;

    for (i = 0; i < npages; i++) {
        struct page *newpage = migrate_pfn_to_page(migrate->dst[i]);
        struct page *page = migrate_pfn_to_page(migrate->src[i]);

        if (!page) {
            if (newpage) {
                unlock_page(newpage);
                put_page(newpage);
            }
            continue;
        }

        if (!(migrate->src[i] & MIGRATE_PFN_MIGRATE) || !newpage) {
            if (newpage) {
                unlock_page(newpage);
                put_page(newpage);
            }
            newpage = page;
        }

        remove_migration_ptes(page, newpage, false);
        unlock_page(page);

        if (is_zone_device_page(page))
            put_page(page);
        else
            putback_lru_page(page);

        if (newpage != page) {
            unlock_page(newpage);
            if (is_zone_device_page(newpage))
                put_page(newpage);
            else
                putback_lru_page(newpage);
        }
    }
}
EXPORT_SYMBOL(migrate_vma_finalize);
#endif /* CONFIG_DEVICE_PRIVATE */
