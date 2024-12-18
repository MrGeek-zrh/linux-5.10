/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REF_H
#define _LINUX_PAGE_REF_H

#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/tracepoint-defs.h>

DECLARE_TRACEPOINT(page_ref_set);
DECLARE_TRACEPOINT(page_ref_mod);
DECLARE_TRACEPOINT(page_ref_mod_and_test);
DECLARE_TRACEPOINT(page_ref_mod_and_return);
DECLARE_TRACEPOINT(page_ref_mod_unless);
DECLARE_TRACEPOINT(page_ref_freeze);
DECLARE_TRACEPOINT(page_ref_unfreeze);

#ifdef CONFIG_DEBUG_PAGE_REF

/*
 * Ideally we would want to use the trace_<tracepoint>_enabled() helper
 * functions. But due to include header file issues, that is not
 * feasible. Instead we have to open code the static key functions.
 *
 * See trace_##name##_enabled(void) in include/linux/tracepoint.h
 */
#define page_ref_tracepoint_active(t) tracepoint_enabled(t)

extern void __page_ref_set(struct page *page, int v);
extern void __page_ref_mod(struct page *page, int v);
extern void __page_ref_mod_and_test(struct page *page, int v, int ret);
extern void __page_ref_mod_and_return(struct page *page, int v, int ret);
extern void __page_ref_mod_unless(struct page *page, int v, int u);
extern void __page_ref_freeze(struct page *page, int v, int ret);
extern void __page_ref_unfreeze(struct page *page, int v);

#else

#endif

static inline int page_ref_count(struct page *page)
{
    return atomic_read(&page->_refcount);
}

/**
 *  获取引用计数page->_refcount
 *
 *  通常情况下，page_count(page) == page_mapcount(page)
 *          即   page->_refcount = page->_mapcount + 1
 *
 *  _refcount 有以下四种来源：
 *  =============================================
 *  1. 页面高速缓存在 radix tree 上， KSM 不考虑 页面高速缓存的情况
 *  2. 被用户态 PTE 引用， _refcount 和 _mapcount 都会增加计数
 *  3. page->private 数据也会增加 _refcount，对于匿名页面，需要判断他是否在交换缓存中
 *  4. 内核操作某些页面时会增加 _refcount, 如 follow_page(),get_user_pages_fast()
 */
static inline int page_count(struct page *page)
{
    return atomic_read(&compound_head(page)->_refcount);
}

static inline void set_page_count(struct page *page, int v)
{
    atomic_set(&page->_refcount, v);
    if (page_ref_tracepoint_active(page_ref_set))
        __page_ref_set(page, v);
}

/*
 * Setup the page count before being freed into the page allocator for
 * the first time (boot or memory hotplug)
 */
static inline void init_page_count(struct page *page)
{
    set_page_count(page, 1);
}

static inline void page_ref_add(struct page *page, int nr)
{
    atomic_add(nr, &page->_refcount);
    if (page_ref_tracepoint_active(page_ref_mod))
        __page_ref_mod(page, nr);
}

static inline void page_ref_sub(struct page *page, int nr)
{
    atomic_sub(nr, &page->_refcount);
    if (page_ref_tracepoint_active(page_ref_mod))
        __page_ref_mod(page, -nr);
}

static inline int page_ref_sub_return(struct page *page, int nr)
{
    int ret = atomic_sub_return(nr, &page->_refcount);

    if (page_ref_tracepoint_active(page_ref_mod_and_return))
        __page_ref_mod_and_return(page, -nr, ret);
    return ret;
}

// 增加页面的引用计数
static inline void page_ref_inc(struct page *page)
{
    atomic_inc(&page->_refcount); /* 引用计数 */
    if (page_ref_tracepoint_active(page_ref_mod))
        __page_ref_mod(page, 1); /* tracepoint */
}

static inline void page_ref_dec(struct page *page)
{
    atomic_dec(&page->_refcount);
    if (page_ref_tracepoint_active(page_ref_mod))
        __page_ref_mod(page, -1);
}

static inline int page_ref_sub_and_test(struct page *page, int nr)
{
    int ret = atomic_sub_and_test(nr, &page->_refcount);

    if (page_ref_tracepoint_active(page_ref_mod_and_test))
        __page_ref_mod_and_test(page, -nr, ret);
    return ret;
}

static inline int page_ref_inc_return(struct page *page)
{
    int ret = atomic_inc_return(&page->_refcount);

    if (page_ref_tracepoint_active(page_ref_mod_and_return))
        __page_ref_mod_and_return(page, 1, ret);
    return ret;
}

static inline int page_ref_dec_and_test(struct page *page)
{
    int ret = atomic_dec_and_test(&page->_refcount);

    if (page_ref_tracepoint_active(page_ref_mod_and_test))
        __page_ref_mod_and_test(page, -1, ret);
    return ret;
}

static inline int page_ref_dec_return(struct page *page)
{
    int ret = atomic_dec_return(&page->_refcount);

    if (page_ref_tracepoint_active(page_ref_mod_and_return))
        __page_ref_mod_and_return(page, -1, ret);
    return ret;
}

/**
 *
 */
static inline int page_ref_add_unless(struct page *page, int nr, int u)
{
    int ret = atomic_add_unless(&page->_refcount, nr, u);

    if (page_ref_tracepoint_active(page_ref_mod_unless))
        __page_ref_mod_unless(page, nr, ret);
    return ret;
}

/**
 *
 */
static inline int page_ref_freeze(struct page *page, int count)
{
    int ret = likely(atomic_cmpxchg(&page->_refcount, count, 0) == count);

    if (page_ref_tracepoint_active(page_ref_freeze))
        __page_ref_freeze(page, count, ret);
    return ret;
}

static inline void page_ref_unfreeze(struct page *page, int count)
{
    VM_BUG_ON_PAGE(page_count(page) != 0, page);
    VM_BUG_ON(count == 0);

    atomic_set_release(&page->_refcount, count);
    if (page_ref_tracepoint_active(page_ref_unfreeze))
        __page_ref_unfreeze(page, count);
}

#endif
