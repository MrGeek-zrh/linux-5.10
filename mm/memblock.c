// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp.	June 2001.
 * Copyright (C) 2001 Peter Bergner.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/poison.h>
#include <linux/pfn.h>
#include <linux/debugfs.h>
#include <linux/kmemleak.h>
#include <linux/seq_file.h>
#include <linux/memblock.h>

#include <asm/sections.h>
#include <linux/io.h>

#include "internal.h"

#define INIT_MEMBLOCK_REGIONS 128
#define INIT_PHYSMEM_REGIONS 4

#ifndef INIT_MEMBLOCK_RESERVED_REGIONS
#define INIT_MEMBLOCK_RESERVED_REGIONS INIT_MEMBLOCK_REGIONS
#endif

/**
 * DOC: memblock overview
 *
 * Memblock is a method of managing memory regions during the early
 * boot period when the usual kernel memory allocators are not up and
 * running.
 *
 * Memblock views the system memory as collections of contiguous
 * regions. There are several types of these collections:
 *
 * * ``memory`` - describes the physical memory available to the
 *   kernel; this may differ from the actual physical memory installed
 *   in the system, for instance when the memory is restricted with
 *   ``mem=`` command line parameter
 * * ``reserved`` - describes the regions that were allocated
 * * ``physmem`` - describes the actual physical memory available during
 *   boot regardless of the possible restrictions and memory hot(un)plug;
 *   the ``physmem`` type is only available on some architectures.
 *
 * Each region is represented by struct memblock_region that
 * defines the region extents, its attributes and NUMA node id on NUMA
 * systems. Every memory type is described by the struct memblock_type
 * which contains an array of memory regions along with
 * the allocator metadata. The "memory" and "reserved" types are nicely
 * wrapped with struct memblock. This structure is statically
 * initialized at build time. The region arrays are initially sized to
 * %INIT_MEMBLOCK_REGIONS for "memory" and %INIT_MEMBLOCK_RESERVED_REGIONS
 * for "reserved". The region array for "physmem" is initially sized to
 * %INIT_PHYSMEM_REGIONS.
 * The memblock_allow_resize() enables automatic resizing of the region
 * arrays during addition of new regions. This feature should be used
 * with care so that memory allocated for the region array will not
 * overlap with areas that should be reserved, for example initrd.
 *
 * The early architecture setup should tell memblock what the physical
 * memory layout is by using memblock_add() or memblock_add_node()
 * functions. The first function does not assign the region to a NUMA
 * node and it is appropriate for UMA systems. Yet, it is possible to
 * use it on NUMA systems as well and assign the region to a NUMA node
 * later in the setup process using memblock_set_node(). The
 * memblock_add_node() performs such an assignment directly.
 *
 * Once memblock is setup the memory can be allocated using one of the
 * API variants:
 *
 * * memblock_phys_alloc*() - these functions return the **physical**
 *   address of the allocated memory
 * * memblock_alloc*() - these functions return the **virtual** address
 *   of the allocated memory.
 *
 * Note, that both API variants use implicit assumptions about allowed
 * memory ranges and the fallback methods. Consult the documentation
 * of memblock_alloc_internal() and memblock_alloc_range_nid()
 * functions for more elaborate description.
 *
 * As the system boot progresses, the architecture specific mem_init()
 * function frees all the memory to the buddy page allocator.
 *
 * Unless an architecture enables %CONFIG_ARCH_KEEP_MEMBLOCK, the
 * memblock data structures (except "physmem") will be discarded after the
 * system initialization completes.
 */

#ifndef CONFIG_NEED_MULTIPLE_NODES
//struct pglist_data __refdata contig_page_data;
//EXPORT_SYMBOL(contig_page_data);
#endif

/**
 *
 */
unsigned long max_low_pfn;
unsigned long min_low_pfn;

/**
 *  arch/arm64/mm/init.c:           max_pfn = max_low_pfn = max;
 *  arch/x86/mm/init_64.c:          max_pfn = end_pfn;
 *  arch/x86/mm/numa_emulation.c:	max_pfn = PHYS_PFN(max_addr);
 *  arch/x86/kernel/setup.c:        max_pfn = e820__end_of_ram_pfn();
 *  arch/x86/kernel/setup.c:        max_pfn = e820__end_of_ram_pfn();
 *  arch/x86/xen/setup.c:           max_pfn = xen_get_pages_limit();
 *  arch/x86/xen/setup.c:           max_pfn = min(max_pfn, xen_start_info->nr_pages);
 */
unsigned long max_pfn; /* 最大帧号 */
unsigned long long max_possible_pfn;

/**
 * @brief
 *
 */
static struct memblock_region __initdata_memblock memblock_memory_init_regions[INIT_MEMBLOCK_REGIONS /*128*/];
static struct memblock_region __initdata_memblock memblock_reserved_init_regions[INIT_MEMBLOCK_RESERVED_REGIONS /*128*/];

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
static struct memblock_region memblock_physmem_init_regions[INIT_PHYSMEM_REGIONS /*128*/];
#endif

/**
 *  初始化 的 memblock
 */
struct memblock __initdata_memblock memblock = {
    memblock.memory.regions = memblock_memory_init_regions,
    memblock.memory.cnt = 1, /* empty dummy entry */
    memblock.memory.max = INIT_MEMBLOCK_REGIONS, /*128*/
    memblock.memory.name = "memory",

    memblock.reserved.regions = memblock_reserved_init_regions,
    memblock.reserved.cnt = 1, /* empty dummy entry */
    memblock.reserved.max = INIT_MEMBLOCK_RESERVED_REGIONS, /*128*/
    memblock.reserved.name = "reserved",

    memblock.bottom_up = false,
    memblock.current_limit = MEMBLOCK_ALLOC_ANYWHERE, /*0xffffffffffffffff*/
};

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
struct memblock_type physmem = {
    physmem.regions = memblock_physmem_init_regions,
    physmem.cnt = 1, /* empty dummy entry */
    physmem.max = INIT_PHYSMEM_REGIONS,
    physmem.name = "physmem",
};
#endif

/*
 * keep a pointer to &memblock.memory in the text section to use it in
 * __next_mem_range() and its helpers.
 *  For architectures that do not keep memblock data after init, this
 * pointer will be reset to NULL at memblock_discard()
 */
static __refdata struct memblock_type *memblock_memory = &memblock.memory;

#define for_each_memblock_type(i, memblock_type, rgn) \
    for (i = 0, rgn = &memblock_type->regions[0]; i < memblock_type->cnt; i++, rgn = &memblock_type->regions[i])

#define memblock_dbg(fmt, ...)           \
    do {                                 \
        if (memblock_debug)              \
            pr_info(fmt, ##__VA_ARGS__); \
    } while (0)

static int __initdata_memblock memblock_debug;
static bool __initdata_memblock system_has_some_mirror = false;
static int __initdata_memblock memblock_can_resize;
static int __initdata_memblock memblock_memory_in_slab = 0;
static int __initdata_memblock memblock_reserved_in_slab = 0;

static enum memblock_flags __init_memblock choose_memblock_flags(void)
{
    return system_has_some_mirror ? MEMBLOCK_MIRROR : MEMBLOCK_NONE;
}

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t memblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
    return *size = min(*size, PHYS_ADDR_MAX - base);
}

/*
 * Address comparison utilities
 */
static unsigned long __init_memblock memblock_addrs_overlap(phys_addr_t base1, phys_addr_t size1, phys_addr_t base2,
                                                            phys_addr_t size2)
{
    return ((base1 < (base2 + size2)) && (base2 < (base1 + size1)));
}

bool __init_memblock memblock_overlaps_region(struct memblock_type *type, phys_addr_t base, phys_addr_t size)
{
    unsigned long i;

    for (i = 0; i < type->cnt; i++)
        if (memblock_addrs_overlap(base, size, type->regions[i].base, type->regions[i].size))
            break;
    return i < type->cnt;
}

/**
 * __memblock_find_range_bottom_up - find free area utility in bottom-up
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Utility called from memblock_find_in_range_node(), find free area bottom-up.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
static phys_addr_t __init_memblock __memblock_find_range_bottom_up(phys_addr_t start, phys_addr_t end, phys_addr_t size,
                                                                   phys_addr_t align, int nid,
                                                                   enum memblock_flags flags)
{
    phys_addr_t this_start, this_end, cand;
    u64 i;

    /**
     *
     */
    for_each_free_mem_range(i, nid, flags, &this_start, &this_end, NULL)
    {
        this_start = clamp(this_start, start, end);
        this_end = clamp(this_end, start, end);

        cand = round_up(this_start, align);
        if (cand < this_end && this_end - cand >= size)
            return cand;
    }

    return 0;
}

/**
 * __memblock_find_range_top_down - find free area utility, in top-down
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Utility called from memblock_find_in_range_node(), find free area top-down.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
static phys_addr_t __init_memblock __memblock_find_range_top_down(phys_addr_t start, phys_addr_t end, phys_addr_t size,
                                                                  phys_addr_t align, int nid, enum memblock_flags flags)
{
    phys_addr_t this_start, this_end, cand;
    u64 i;

    for_each_free_mem_range_reverse(i, nid, flags, &this_start, &this_end, NULL)
    {
        this_start = clamp(this_start, start, end);
        this_end = clamp(this_end, start, end);

        if (this_end < size)
            continue;

        cand = round_down(this_end - size, align);
        if (cand >= this_start)
            return cand;
    }

    return 0;
}

/**
 * memblock_find_in_range_node - find free area in given range and node
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Find @size free area aligned to @align in the specified range and node.
 *
 * When allocation direction is bottom-up, the @start should be greater
 * than the end of the kernel image. Otherwise, it will be trimmed. The
 * reason is that we want the bottom-up allocation just near the kernel
 * image so it is highly likely that the allocated memory and the kernel
 * will reside in the same node.
 *
 * If bottom-up allocation failed, will try to allocate memory top-down.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
static phys_addr_t __init_memblock memblock_find_in_range_node(phys_addr_t size, phys_addr_t align, phys_addr_t start,
                                                               phys_addr_t end, int nid, enum memblock_flags flags)
{
    phys_addr_t kernel_end, ret;

    /* pump up @end */
    if (end == MEMBLOCK_ALLOC_ACCESSIBLE || end == MEMBLOCK_ALLOC_KASAN)
        end = memblock.current_limit;

    /* avoid allocating the first page */
    start = max_t(phys_addr_t, start, PAGE_SIZE);
    end = max(start, end);
    kernel_end = __pa_symbol(_end);

    /*
	 * try bottom-up allocation only when bottom-up mode
	 * is set and @end is above the kernel image.
	 */
    if (memblock_bottom_up() && end > kernel_end) {
        phys_addr_t bottom_up_start;

        /* make sure we will allocate above the kernel */
        bottom_up_start = max(start, kernel_end);

        /* ok, try bottom-up allocation first */
        ret = __memblock_find_range_bottom_up(bottom_up_start, end, size, align, nid, flags);
        if (ret)
            return ret;

        /*
		 * we always limit bottom-up allocation above the kernel,
		 * but top-down allocation doesn't have the limit, so
		 * retrying top-down allocation may succeed when bottom-up
		 * allocation failed.
		 *
		 * bottom-up allocation is expected to be fail very rarely,
		 * so we use WARN_ONCE() here to see the stack trace if
		 * fail happens.
		 */
        WARN_ONCE(IS_ENABLED(CONFIG_MEMORY_HOTREMOVE),
                  "memblock: bottom-up allocation failed, memory hotremove may be affected\n");
    }

    return __memblock_find_range_top_down(start, end, size, align, nid, flags);
}

/**
 * memblock_find_in_range - find free area in given range
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
phys_addr_t __init_memblock memblock_find_in_range(phys_addr_t start, phys_addr_t end, phys_addr_t size,
                                                   phys_addr_t align)
{
    phys_addr_t ret;
    enum memblock_flags flags = choose_memblock_flags();

again:
    ret = memblock_find_in_range_node(size, align, start, end, NUMA_NO_NODE, flags);

    if (!ret && (flags & MEMBLOCK_MIRROR)) {
        pr_warn("Could not allocate %pap bytes of mirrored memory\n", &size);
        flags &= ~MEMBLOCK_MIRROR;
        goto again;
    }

    return ret;
}

/**
 *  移除一个 region
 */
static void __init_memblock memblock_remove_region(struct memblock_type *type, unsigned long r)
{
    type->total_size -= type->regions[r].size;
    memmove(&type->regions[r], &type->regions[r + 1], (type->cnt - (r + 1)) * sizeof(type->regions[r]));

    type->cnt--;

    /* Special case for empty arrays */
    if (type->cnt == 0) {
        WARN_ON(type->total_size != 0);
        type->cnt = 1;
        type->regions[0].base = 0;
        type->regions[0].size = 0;
        type->regions[0].flags = 0;

        /**
         *  将 NODE ID 设置为 无效
         */
        memblock_set_region_node(&type->regions[0], MAX_NUMNODES);
    }
}

#ifndef CONFIG_ARCH_KEEP_MEMBLOCK
/**
 * memblock_discard - discard memory and reserved arrays if they were allocated
 */
void __init memblock_discard(void)
{
    phys_addr_t addr, size;

    if (memblock.reserved.regions != memblock_reserved_init_regions) {
        addr = __pa(memblock.reserved.regions);
        size = PAGE_ALIGN(sizeof(struct memblock_region) * memblock.reserved.max);
        __memblock_free_late(addr, size);
    }

    if (memblock.memory.regions != memblock_memory_init_regions) {
        addr = __pa(memblock.memory.regions);
        size = PAGE_ALIGN(sizeof(struct memblock_region) * memblock.memory.max);
        __memblock_free_late(addr, size);
    }

    memblock_memory = NULL;
}
#endif

/**
 * memblock_double_array - double the size of the memblock regions array
 * @type: memblock type of the regions array being doubled
 * @new_area_start: starting address of memory range to avoid overlap with
 * @new_area_size: size of memory range to avoid overlap with
 *
 * Double the size of the @type regions array. If memblock is being used to
 * allocate memory for a new reserved regions array and there is a previously
 * allocated memory range [@new_area_start, @new_area_start + @new_area_size]
 * waiting to be reserved, ensure the memory used by the new array does
 * not overlap.
 *
 * Return:
 * 0 on success, -1 on failure.
 *//* 双倍 TODO */
static int __init_memblock memblock_double_array(struct memblock_type *type, phys_addr_t new_area_start,
                                                 phys_addr_t new_area_size)
{
    struct memblock_region *new_array, *old_array;
    phys_addr_t old_alloc_size, new_alloc_size;
    phys_addr_t old_size, new_size, addr, new_end;
    int use_slab = slab_is_available(); /* slab 分配器的状态 */
    int *in_slab;

    /* We don't allow resizing until we know about the reserved regions
	 * of memory that aren't suitable for allocation
	 */
    if (!memblock_can_resize)
        return -1;

    /* Calculate new doubled size */
    old_size = type->max * sizeof(struct memblock_region);
    new_size = old_size << 1;
    /*
	 * We need to allocated new one align to PAGE_SIZE,
	 *   so we can free them completely later.
	 */
    old_alloc_size = PAGE_ALIGN(old_size);
    new_alloc_size = PAGE_ALIGN(new_size);

    /* Retrieve the slab flag */
    if (type == &memblock.memory)
        in_slab = &memblock_memory_in_slab;
    else
        in_slab = &memblock_reserved_in_slab;

    /* Try to find some space for it */
    if (use_slab) {
        new_array = kmalloc(new_size, GFP_KERNEL);
        addr = new_array ? __pa(new_array) : 0;
    } else {
        /* only exclude range when trying to double reserved.regions */
        if (type != &memblock.reserved)
            new_area_start = new_area_size = 0;

        addr = memblock_find_in_range(new_area_start + new_area_size, memblock.current_limit, new_alloc_size,
                                      PAGE_SIZE);
        if (!addr && new_area_size)
            addr = memblock_find_in_range(0, min(new_area_start, memblock.current_limit), new_alloc_size, PAGE_SIZE);

        new_array = addr ? __va(addr) : NULL;
    }
    if (!addr) {
        pr_err("memblock: Failed to double %s array from %ld to %ld entries !\n", type->name, type->max, type->max * 2);
        return -1;
    }

    new_end = addr + new_size - 1;
    memblock_dbg("memblock: %s is doubled to %ld at [%pa-%pa]", type->name, type->max * 2, &addr, &new_end);

    /*
	 * Found space, we now need to move the array over before we add the
	 * reserved region since it may be our reserved array itself that is
	 * full.
	 */
    memcpy(new_array, type->regions, old_size);
    memset(new_array + type->max, 0, old_size);
    old_array = type->regions;
    type->regions = new_array;
    type->max <<= 1;

    /* Free old array. We needn't free it if the array is the static one */
    if (*in_slab)
        kfree(old_array);
    else if (old_array != memblock_memory_init_regions && old_array != memblock_reserved_init_regions)
        memblock_free(__pa(old_array), old_alloc_size);

    /*
	 * Reserve the new array if that comes from the memblock.  Otherwise, we
	 * needn't do it
	 */
    if (!use_slab)
        BUG_ON(memblock_reserve(addr, new_alloc_size));

    /* Update slab flag */
    *in_slab = use_slab;

    return 0;
}

/**
 * memblock_merge_regions - merge neighboring compatible regions
 * @type: memblock type to scan
 *
 * Scan @type and merge neighboring compatible regions.
 */
static void __init_memblock memblock_merge_regions(struct memblock_type *type)
{
    int i = 0;

    /* cnt never goes below 1 */
    while (i < type->cnt - 1) {
        struct memblock_region *this = &type->regions[i];
        struct memblock_region *next = &type->regions[i + 1];

        if (this->base + this->size != next->base || memblock_get_region_node(this) != memblock_get_region_node(next) ||
            this->flags != next->flags) {
            BUG_ON(this->base + this->size > next->base);
            i++;
            continue;
        }

        this->size += next->size;
        /* move forward from next + 1, index of which is i + 2 */
        memmove(next, next + 1, (type->cnt - (i + 2)) * sizeof(*next));
        type->cnt--;
    }
}

/**
 * memblock_insert_region - insert new memblock region
 * @type:	memblock type to insert into
 * @idx:	index for the insertion point
 * @base:	base address of the new region
 * @size:	size of the new region
 * @nid:	node id of the new region
 * @flags:	flags of the new region
 *
 * Insert new memblock region [@base, @base + @size) into @type at @idx.
 * @type must already have extra room to accommodate the new region.
 */
static void __init_memblock memblock_insert_region(struct memblock_type *type, int idx, phys_addr_t base,
                                                   phys_addr_t size, int nid, enum memblock_flags flags)
{
    struct memblock_region *rgn = &type->regions[idx];

    BUG_ON(type->cnt >= type->max);
    memmove(rgn + 1, rgn, (type->cnt - idx) * sizeof(*rgn));
    rgn->base = base;
    rgn->size = size;
    rgn->flags = flags;
    memblock_set_region_node(rgn, nid);
    type->cnt++;
    type->total_size += size;
}

/**
 * memblock_add_range - add new memblock region
 * @type: memblock type to add new region into
 * @base: base address of the new region,    内存区域的物理基地址
 * @size: size of the new region,    内存区域的大小
 * @nid: nid of the new region,  最大 NUMA 节点数
 * @flags: flags of the new region,  标志参数 flags
 *
 *
 * Add new memblock region [@base, @base + @size) into @type.  The new region
 * is allowed to overlap with existing ones - overlaps don't affect already
 * existing regions.  @type is guaranteed to be minimal (all neighbouring
 * compatible regions are merged) after the addition.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
//0                    0x1000
//+-----------------------+
//|        region1        |
//+-----------------------+
//
//0x100                 0x2000
//+-----------------------+
//|        region2        |
//+-----------------------+
//成功地将两个内存区域合并 ==>
//0                                             0x2000
//+------------------------------------------------+
//|                   region1                      |
//+------------------------------------------------+

static int __init_memblock memblock_add_range(struct memblock_type *type, phys_addr_t base, phys_addr_t size, int nid,
                                              enum memblock_flags flags)
{
    bool insert = false;
    phys_addr_t obase = base;
    phys_addr_t end = base + memblock_cap_size(base, &size);
    int idx, nr_new;
    struct memblock_region *rgn;
    /*
    --
    |
    |
    |
    |
    |<--end
    |
    |
    |
    |<--base = obase
    |
    |
    |
    --
    */
    if (!size)
        return 0;

    /* special case for empty array */
    if (type->regions[0].size == 0) {
        WARN_ON(type->cnt != 1 || type->total_size);
        type->regions[0].base = base;
        type->regions[0].size = size;
        type->regions[0].flags = flags;
        memblock_set_region_node(&type->regions[0], nid);
        type->total_size = size;
        return 0;
    }
repeat:
    /*
	 * The following is executed twice.  Once with %false @insert and
	 * then with %true.  The first counts the number of regions needed
	 * to accommodate the new area.  The second actually inserts them.
	 */
    /*
    --
    |
    |
    |
    |
    |<--end
    |
    |
    |
    |<--base = obase
    |
    |
    |
    --
    */
    base = obase;
    nr_new = 0;

    for_each_memblock_type(idx, type, rgn)
    { /* 遍历 memblock_type 的所有 region */
        phys_addr_t rbase = rgn->base; /* region base 地址 */
        phys_addr_t rend = rbase + rgn->size; /* 大小 */
        /*
        --
        |
        |
        |
        |       <--rbase
        |<--end
        |
        |
        |
        |<--base = obase
        |
        |
        |
        --
        */
        if (rbase >= end) /* region 基址 已经大于 要插入的 基址， 直接退出 */
            break;
        /*
        --
        |
        |
        |
        |
        |<--end
        |
        |
        |
        |<--base
        |
        |       <--rend
        |
        -- 继续遍历下一个 region
        */
        if (rend <= base)
            continue;
        /*
		 * @rgn overlaps.  If it separates the lower part of new
		 * area, insert that portion.
		 *//*
        --
        |
        |
        |
        |
        |<--end
        |       <--rend
        |
        |       <--rbase
        |<--base
        |
        |
        |
        --
        */
        if (rbase > base) {
#ifdef CONFIG_NEED_MULTIPLE_NODES
            WARN_ON(nid != memblock_get_region_node(rgn));
#endif
            WARN_ON(flags != rgn->flags);
            nr_new++;
            if (insert)
                memblock_insert_region(type, idx++, base, rbase - base, nid, flags);
        }
        /* area below @rend is dealt with, forget about it */
        base = min(rend, end);
    }

    /* insert the remaining portion */
    if (base < end) {
        nr_new++;
        if (insert)
            memblock_insert_region(type, idx, base, end - base, nid, flags);
    }

    if (!nr_new)
        return 0;

    /*
	 * If this was the first round, resize array and repeat for actual
	 * insertions; otherwise, merge and return.
	 */
    if (!insert) {
        while (type->cnt + nr_new > type->max)
            if (memblock_double_array(type, obase, size) < 0)
                return -ENOMEM;
        insert = true;
        goto repeat;
    } else {
        memblock_merge_regions(type);
        return 0;
    }
}

/**
 * memblock_add_node - add new memblock region within a NUMA node
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add_node(phys_addr_t base, phys_addr_t size, int nid)
{
    return memblock_add_range(&memblock.memory, base, size, nid, 0);
}

/**
 * memblock_add - add new memblock region
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__, &base, &end, (void *)_RET_IP_);

    /**
     *  添加
     */
    return memblock_add_range(&memblock.memory, base, size, MAX_NUMNODES, 0);
}

/**
 * memblock_isolate_range - isolate given range into disjoint memblocks
 * @type: memblock type to isolate range for
 * @base: base of range to isolate
 * @size: size of range to isolate
 * @start_rgn: out parameter for the start of isolated region
 * @end_rgn: out parameter for the end of isolated region
 *
 * Walk @type and ensure that regions don't cross the boundaries defined by
 * [@base, @base + @size).  Crossing regions are split at the boundaries,
 * which may create at most two more regions.  The index of the first
 * region inside the range is returned in *@start_rgn and end in *@end_rgn.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
static int __init_memblock memblock_isolate_range(struct memblock_type *type, phys_addr_t base, phys_addr_t size,
                                                  int *start_rgn, int *end_rgn)
{
    phys_addr_t end = base + memblock_cap_size(base, &size) /* 获取大小 */; /* 获取结束地址 */
    int idx;
    struct memblock_region *rgn;

    *start_rgn = *end_rgn = 0;

    if (!size)
        return 0;

    /* we'll create at most two more regions */
    while (type->cnt + 2 > type->max)
        if (memblock_double_array(type, base, size) < 0)
            return -ENOMEM;

    for_each_memblock_type(idx, type, rgn)
    {
        phys_addr_t rbase = rgn->base;
        phys_addr_t rend = rbase + rgn->size;

        if (rbase >= end)
            break;
        if (rend <= base)
            continue;

        if (rbase < base) {
            /*
			 * @rgn intersects from below.  Split and continue
			 * to process the next region - the new top half.
			 */
            rgn->base = base;
            rgn->size -= base - rbase;
            type->total_size -= base - rbase;
            memblock_insert_region(type, idx, rbase, base - rbase, memblock_get_region_node(rgn), rgn->flags);
        } else if (rend > end) {
            /*
			 * @rgn intersects from above.  Split and redo the
			 * current region - the new bottom half.
			 */
            rgn->base = end;
            rgn->size -= end - rbase;
            type->total_size -= end - rbase;
            memblock_insert_region(type, idx--, rbase, end - rbase, memblock_get_region_node(rgn), rgn->flags);
        } else {
            /* @rgn is fully contained, record it */
            if (!*end_rgn)
                *start_rgn = idx;
            *end_rgn = idx + 1;
        }
    }

    return 0;
}

static int __init_memblock memblock_remove_range(struct memblock_type *type, phys_addr_t base, phys_addr_t size)
{
    int start_rgn, end_rgn;
    int i, ret;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
    if (ret)
        return ret;

    for (i = end_rgn - 1; i >= start_rgn; i--)
        memblock_remove_region(type, i);
    return 0;
}

/**
 *
 */
int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__, &base, &end, (void *)_RET_IP_);

    return memblock_remove_range(&memblock.memory, base, size);
}

/**
 * memblock_free - free boot memory block
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
int __init_memblock memblock_free(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__, &base, &end, (void *)_RET_IP_);

    kmemleak_free_part_phys(base, size);
    return memblock_remove_range(&memblock.reserved, base, size);
}

/* 在给定的基地址处预留指定大小的内存
    @ base = 基物理地址
    @ size = 区域大小
*/
int __init_memblock memblock_reserve(phys_addr_t base, phys_addr_t size) /* 内存预留 */
{
    phys_addr_t end = base + size - 1; /* 结束地址 */

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__, &base, &end, (void *)_RET_IP_);

    /**
     *  添加到 reserved
     */
    return memblock_add_range(&memblock.reserved, base, size, MAX_NUMNODES, 0);
}

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
//int __init_memblock memblock_physmem_add(phys_addr_t base, phys_addr_t size)
//{
//	phys_addr_t end = base + size - 1;
//
//	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__, &base, &end, (void *)_RET_IP_);
//
//	return memblock_add_range(&physmem, base, size, MAX_NUMNODES, 0);
//}
#endif

/**
 * memblock_setclr_flag - set or clear flag for a memory region
 * @base: base address of the region
 * @size: size of the region
 * @set: set or clear the flag
 * @flag: the flag to udpate
 *
 * This function isolates region [@base, @base + @size), and sets/clears flag
 *
 * Return: 0 on success, -errno on failure.
 */
static int __init_memblock memblock_setclr_flag(phys_addr_t base, phys_addr_t size, int set, int flag)
{
    struct memblock_type *type = &memblock.memory;
    int i, ret, start_rgn, end_rgn;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn); /* 从 base 到 region */
    if (ret)
        return ret;

    for (i = start_rgn; i < end_rgn; i++) {
        struct memblock_region *r = &type->regions[i];

        if (set)
            r->flags |= flag;
        else
            r->flags &= ~flag;
    }

    memblock_merge_regions(type);
    return 0;
}

/**
 * memblock_mark_hotplug - Mark hotpluggable memory with flag MEMBLOCK_HOTPLUG.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_hotplug(phys_addr_t base, phys_addr_t size)
{
    return memblock_setclr_flag(base, size, 1, MEMBLOCK_HOTPLUG);
}

/**
 * memblock_clear_hotplug - Clear flag MEMBLOCK_HOTPLUG for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_clear_hotplug(phys_addr_t base, phys_addr_t size)
{
    return memblock_setclr_flag(base, size, 0, MEMBLOCK_HOTPLUG);
}

/**
 * memblock_mark_mirror - Mark mirrored memory with flag MEMBLOCK_MIRROR.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_mirror(phys_addr_t base, phys_addr_t size)
{
    system_has_some_mirror = true;

    return memblock_setclr_flag(base, size, 1, MEMBLOCK_MIRROR);
}

/**
 * memblock_mark_nomap - Mark a memory region with flag MEMBLOCK_NOMAP.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_nomap(phys_addr_t base, phys_addr_t size)
{
    return memblock_setclr_flag(base, size, 1, MEMBLOCK_NOMAP);
}

/**
 * memblock_clear_nomap - Clear flag MEMBLOCK_NOMAP for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
{
    return memblock_setclr_flag(base, size, 0, MEMBLOCK_NOMAP);
}

static bool should_skip_region(struct memblock_type *type, struct memblock_region *m, int nid, int flags)
{
    int m_nid = memblock_get_region_node(m);

    /* we never skip regions when iterating memblock.reserved or physmem */
    if (type != memblock_memory)
        return false;

    /* only memory regions are associated with nodes, check it */
    if (nid != NUMA_NO_NODE && nid != m_nid)
        return true;

    /* skip hotpluggable memory regions if needed */
    if (movable_node_is_enabled() && memblock_is_hotpluggable(m))
        return true;

    /* if we want mirror memory skip non-mirror memory regions */
    if ((flags & MEMBLOCK_MIRROR) && !memblock_is_mirror(m))
        return true;

    /* skip nomap memory unless we were asked for it explicitly */
    if (!(flags & MEMBLOCK_NOMAP) && memblock_is_nomap(m))
        return true;

    return false;
}

/**
 * __next_mem_range - next function for for_each_free_mem_range() etc.
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Find the first area from *@idx which matches @nid, fill the out
 * parameters, and update *@idx for the next iteration.  The lower 32bit of
 * *@idx contains index into type_a and the upper 32bit indexes the
 * areas before each region in type_b.	For example, if type_b regions
 * look like the following,
 *
 *	0:[0-16), 1:[32-48), 2:[128-130)
 *
 * The upper 32bit indexes the following regions.
 *
 *	0:[0-0), 1:[16-32), 2:[48-128), 3:[130-MAX)
 *
 * As both region arrays are sorted, the function advances the two indices
 * in lockstep and returns each intersection.
 */
void __next_mem_range(u64 *idx, int nid, enum memblock_flags flags, struct memblock_type *type_a,
                      struct memblock_type *type_b, phys_addr_t *out_start, phys_addr_t *out_end, int *out_nid)
{
    int idx_a = *idx & 0xffffffff;
    int idx_b = *idx >> 32;

    if (WARN_ONCE(nid == MAX_NUMNODES, "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
        nid = NUMA_NO_NODE;

    for (; idx_a < type_a->cnt; idx_a++) {
        struct memblock_region *m = &type_a->regions[idx_a];

        phys_addr_t m_start = m->base;
        phys_addr_t m_end = m->base + m->size;
        int m_nid = memblock_get_region_node(m);

        if (should_skip_region(type_a, m, nid, flags))
            continue;

        if (!type_b) {
            if (out_start)
                *out_start = m_start;
            if (out_end)
                *out_end = m_end;
            if (out_nid)
                *out_nid = m_nid;
            idx_a++;
            *idx = (u32)idx_a | (u64)idx_b << 32;
            return;
        }

        /* scan areas before each reservation */
        for (; idx_b < type_b->cnt + 1; idx_b++) {
            struct memblock_region *r;
            phys_addr_t r_start;
            phys_addr_t r_end;

            r = &type_b->regions[idx_b];
            r_start = idx_b ? r[-1].base + r[-1].size : 0;
            r_end = idx_b < type_b->cnt ? r->base : PHYS_ADDR_MAX;

            /*
			 * if idx_b advanced past idx_a,
			 * break out to advance idx_a
			 */
            if (r_start >= m_end)
                break;
            /* if the two regions intersect, we're done */
            if (m_start < r_end) {
                if (out_start)
                    *out_start = max(m_start, r_start);
                if (out_end)
                    *out_end = min(m_end, r_end);
                if (out_nid)
                    *out_nid = m_nid;
                /*
				 * The region which ends first is
				 * advanced for the next iteration.
				 */
                if (m_end <= r_end)
                    idx_a++;
                else
                    idx_b++;
                *idx = (u32)idx_a | (u64)idx_b << 32;
                return;
            }
        }
    }

    /* signal end of iteration */
    *idx = ULLONG_MAX;
}

/**
 * __next_mem_range_rev - generic next function for for_each_*_range_rev()
 *
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Finds the next range from type_a which is not marked as unsuitable
 * in type_b.
 *
 * Reverse of __next_mem_range().
 */
void __init_memblock __next_mem_range_rev(u64 *idx, int nid, enum memblock_flags flags, struct memblock_type *type_a,
                                          struct memblock_type *type_b, phys_addr_t *out_start, phys_addr_t *out_end,
                                          int *out_nid)
{
    int idx_a = *idx & 0xffffffff;
    int idx_b = *idx >> 32;

    if (WARN_ONCE(nid == MAX_NUMNODES, "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
        nid = NUMA_NO_NODE;

    if (*idx == (u64)ULLONG_MAX) {
        idx_a = type_a->cnt - 1;
        if (type_b != NULL)
            idx_b = type_b->cnt;
        else
            idx_b = 0;
    }

    for (; idx_a >= 0; idx_a--) {
        struct memblock_region *m = &type_a->regions[idx_a];

        phys_addr_t m_start = m->base;
        phys_addr_t m_end = m->base + m->size;
        int m_nid = memblock_get_region_node(m);

        if (should_skip_region(type_a, m, nid, flags))
            continue;

        if (!type_b) {
            if (out_start)
                *out_start = m_start;
            if (out_end)
                *out_end = m_end;
            if (out_nid)
                *out_nid = m_nid;
            idx_a--;
            *idx = (u32)idx_a | (u64)idx_b << 32;
            return;
        }

        /* scan areas before each reservation */
        for (; idx_b >= 0; idx_b--) {
            struct memblock_region *r;
            phys_addr_t r_start;
            phys_addr_t r_end;

            r = &type_b->regions[idx_b];
            r_start = idx_b ? r[-1].base + r[-1].size : 0;
            r_end = idx_b < type_b->cnt ? r->base : PHYS_ADDR_MAX;
            /*
			 * if idx_b advanced past idx_a,
			 * break out to advance idx_a
			 */

            if (r_end <= m_start)
                break;
            /* if the two regions intersect, we're done */
            if (m_end > r_start) {
                if (out_start)
                    *out_start = max(m_start, r_start);
                if (out_end)
                    *out_end = min(m_end, r_end);
                if (out_nid)
                    *out_nid = m_nid;
                if (m_start >= r_start)
                    idx_a--;
                else
                    idx_b--;
                *idx = (u32)idx_a | (u64)idx_b << 32;
                return;
            }
        }
    }
    /* signal end of iteration */
    *idx = ULLONG_MAX;
}

/*
 * Common iterator interface used to define for_each_mem_pfn_range().
 */
void __init_memblock __next_mem_pfn_range(int *idx, int nid, unsigned long *out_start_pfn, unsigned long *out_end_pfn,
                                          int *out_nid)
{
    /**
     *  从 memblock 接管内存
     */
    struct memblock_type *type = &memblock.memory;
    struct memblock_region *r;
    int r_nid;

    /**
     *
     */
    while (++*idx < type->cnt) {
        r = &type->regions[*idx];

        /**
         *  获取 node ID
         */
        r_nid = memblock_get_region_node(r);

        /**
         *  检查地址合理性
         */
        if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
            continue;

        /**
         *  nid 合理性，找到了 nid，然后获取 pfn
         */
        if (nid == MAX_NUMNODES || nid == r_nid)
            break;
    }

    if (*idx >= type->cnt) {
        *idx = -1;
        return;
    }

    /**
     *  返回这个 memblock region 的  物理帧号 范围
     */
    if (out_start_pfn)
        *out_start_pfn = PFN_UP(r->base);
    if (out_end_pfn)
        *out_end_pfn = PFN_DOWN(r->base + r->size);
    if (out_nid)
        *out_nid = r_nid;
}

/**
 * memblock_set_node - set node ID on memblock regions
 * @base: base of area to set node ID for
 * @size: size of area to set node ID for
 * @type: memblock type to set node ID for
 * @nid: node ID to set
 *
 * Set the nid of memblock @type regions in [@base, @base + @size) to @nid.
 * Regions which cross the area boundaries are split as necessary.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_set_node(phys_addr_t base, phys_addr_t size, struct memblock_type *type, int nid)
{
#ifdef CONFIG_NEED_MULTIPLE_NODES
    int start_rgn, end_rgn;
    int i, ret;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
    if (ret)
        return ret;

    for (i = start_rgn; i < end_rgn; i++)
        memblock_set_region_node(&type->regions[i], nid);

    memblock_merge_regions(type);
#endif
    return 0;
}

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
/**
 * __next_mem_pfn_range_in_zone - iterator for for_each_*_range_in_zone()
 *
 * @idx: pointer to u64 loop variable
 * @zone: zone in which all of the memory blocks reside
 * @out_spfn: ptr to ulong for start pfn of the range, can be %NULL
 * @out_epfn: ptr to ulong for end pfn of the range, can be %NULL
 *
 * This function is meant to be a zone/pfn specific wrapper for the
 * for_each_mem_range type iterators. Specifically they are used in the
 * deferred memory init routines and as such we were duplicating much of
 * this logic throughout the code. So instead of having it in multiple
 * locations it seemed like it would make more sense to centralize this to
 * one new iterator that does everything they need.
 */
void __init_memblock __next_mem_pfn_range_in_zone(u64 *idx, struct zone *zone, unsigned long *out_spfn,
                                                  unsigned long *out_epfn)
{
    int zone_nid = zone_to_nid(zone);
    phys_addr_t spa, epa;
    int nid;

    __next_mem_range(idx, zone_nid, MEMBLOCK_NONE, &memblock.memory, &memblock.reserved, &spa, &epa, &nid);

    while (*idx != U64_MAX) {
        unsigned long epfn = PFN_DOWN(epa);
        unsigned long spfn = PFN_UP(spa);

        /*
		 * Verify the end is at least past the start of the zone and
		 * that we have at least one PFN to initialize.
		 */
        if (zone->zone_start_pfn < epfn && spfn < epfn) {
            /* if we went too far just stop searching */
            if (zone_end_pfn(zone) <= spfn) {
                *idx = U64_MAX;
                break;
            }

            if (out_spfn)
                *out_spfn = max(zone->zone_start_pfn, spfn);
            if (out_epfn)
                *out_epfn = min(zone_end_pfn(zone), epfn);

            return;
        }

        __next_mem_range(idx, zone_nid, MEMBLOCK_NONE, &memblock.memory, &memblock.reserved, &spa, &epa, &nid);
    }

    /* signal end of iteration */
    if (out_spfn)
        *out_spfn = ULONG_MAX;
    if (out_epfn)
        *out_epfn = 0;
}

#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

/**
 * memblock_alloc_range_nid - 分配启动内存块
 *
 * @size: 要分配的内存块大小(字节)
 * @align: 内存区域和块大小的对齐要求
 * @start: 分配内存区域的下界(物理地址)
 * @end: 分配内存区域的上界(物理地址)
 * @nid: 要查找的空闲区域的 NUMA 节点 ID,如果是 NUMA_NO_NODE 则表示任意节点
 * @exact_nid: 控制是否允许分配回退到其他节点
 *
 * 如果 @end == MEMBLOCK_ALLOC_ACCESSIBLE,则从 memblock.current_limit 限制的
 * 内存区域中进行分配。
 *
 * 如果指定的节点无法容纳请求的内存,且 @exact_nid 为 false,则分配会回退到
 * 系统中的任意节点。
 *
 * 对于具有内存镜像的系统,首先尝试从启用镜像的区域分配,然后从任意内存区域
 * 重试。
 *
 * 此外,该函数使用 kmemleak_alloc_phys 将已分配的启动内存块的 min_count 设置
 * 为 0,因此它永远不会被报告为内存泄漏。
 *
 * 返回值:
 * 成功时返回已分配内存块的物理地址,失败时返回 0。
 */
phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size, phys_addr_t align, phys_addr_t start, phys_addr_t end,
                                            int nid, bool exact_nid)
{
    // 判断当前系统有没有镜像内存，如果有，设置MEMBLOCK_MIRROR
    enum memblock_flags flags = choose_memblock_flags();
    phys_addr_t found;

    if (WARN_ONCE(nid == MAX_NUMNODES, "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
        nid = NUMA_NO_NODE;

    if (!align) {
        /* Can't use WARNs this early in boot on powerpc */
        dump_stack();
        align = SMP_CACHE_BYTES;
    }

again:
    /**
     *
     */
    found = memblock_find_in_range_node(size, align, start, end, nid, flags);
    if (found && !memblock_reserve(found, size))
        goto done;

    if (nid != NUMA_NO_NODE && !exact_nid) {
        found = memblock_find_in_range_node(size, align, start, end, NUMA_NO_NODE, flags);
        /* 
         * 如果找到了内存区域,则将其加入到reserved中
         * 因为这块内存已经被分配出去了,需要标记为已保留
         * 防止这块内存被其他分配请求重复使用
         */
        if (found && !memblock_reserve(found, size))
            goto done;
    }

    if (flags & MEMBLOCK_MIRROR) {
        flags &= ~MEMBLOCK_MIRROR;
        pr_warn("Could not allocate %pap bytes of mirrored memory\n", &size);
        goto again;
    }

    return 0;

done:
    /* Skip kmemleak for kasan_init() due to high volume. */
    if (end != MEMBLOCK_ALLOC_KASAN)
        /*
         * min_count 设置为 0 是为了防止 memblock 分配的内存块被报告为内存泄漏。
         * 这是因为这些内存块通常只能通过物理地址访问,而 kmemleak 不会查找物理地址。
         * 
         * kmemleak_alloc_phys() 用于跟踪物理内存分配:
         * - found: 分配的物理地址
         * - size: 分配的大小
         * - min_count: 设为0,表示不检查泄漏
         * - flags: 设为0,不使用特殊标记
         */
        kmemleak_alloc_phys(found, size, 0, 0);

    return found;
}

/**
 * memblock_phys_alloc_range - allocate a memory block inside specified range
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @start: the lower bound of the memory region to allocate (physical address)
 * @end: the upper bound of the memory region to allocate (physical address)
 *
 * Allocate @size bytes in the between @start and @end.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 */
phys_addr_t __init memblock_phys_alloc_range(phys_addr_t size, phys_addr_t align, phys_addr_t start, phys_addr_t end)
{
    return memblock_alloc_range_nid(size, align, start, end, NUMA_NO_NODE, false);
}

/**
 * memblock_phys_alloc_try_nid - allocate a memory block from specified MUMA node
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Allocates memory block from the specified NUMA node. If the node
 * has no available memory, attempts to allocated from any node in the
 * system.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 */
phys_addr_t __init memblock_phys_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid)
{
    return memblock_alloc_range_nid(size, align, 0, MEMBLOCK_ALLOC_ACCESSIBLE, nid, false);
}

/**
 * memblock_alloc_internal - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region to allocate (phys address)
 * @max_addr: the upper bound of the memory region to allocate (phys address)
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @exact_nid: control the allocation fall back to other nodes
 *
 * Allocates memory block using memblock_alloc_range_nid() and
 * converts the returned physical address to virtual.
 *
 * The @min_addr limit is dropped if it can not be satisfied and the allocation
 * will fall back to memory below @min_addr. Other constraints, such
 * as node and mirrored memory will be handled again in
 * memblock_alloc_range_nid().
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
static void *__init memblock_alloc_internal(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                            phys_addr_t max_addr, int nid, bool exact_nid)
{
    phys_addr_t alloc;

    /*
	 * Detect any accidental use of these APIs after slab is ready, as at
	 * this moment memblock may be deinitialized already and its
	 * internal data may be destroyed (after execution of memblock_free_all)
	 */
    if (WARN_ON_ONCE(slab_is_available()))
        return kzalloc_node(size, GFP_NOWAIT, nid);

    if (max_addr > memblock.current_limit)
        max_addr = memblock.current_limit;

    /**
     *  分配
     */
    alloc = memblock_alloc_range_nid(size, align, min_addr, max_addr, nid, exact_nid);

    /* retry allocation without lower limit */
    if (!alloc && min_addr)
        alloc = memblock_alloc_range_nid(size, align, 0, max_addr, nid, exact_nid);

    if (!alloc)
        return NULL;

    /**
     *  返回虚拟地址
     */
    return phys_to_virt(alloc);
}

/**
 * memblock_alloc_exact_nid_raw - allocate boot memory block on the exact node
 * without zeroing memory
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. Does not zero allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void *__init memblock_alloc_exact_nid_raw(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                          phys_addr_t max_addr, int nid)
{
    void *ptr;

    memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n", __func__, (u64)size, (u64)align, nid,
                 &min_addr, &max_addr, (void *)_RET_IP_);

    ptr = memblock_alloc_internal(size, align, min_addr, max_addr, nid, true);
    if (ptr && size > 0)
        page_init_poison(ptr, size);

    return ptr;
}

/**
 * memblock_alloc_try_nid_raw - allocate boot memory block without zeroing
 * memory and without panicking
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. Does not zero allocated memory, does not panic if request
 * cannot be satisfied.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void *__init memblock_alloc_try_nid_raw(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr, phys_addr_t max_addr,
                                        int nid)
{
    void *ptr;

    memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n", __func__, (u64)size, (u64)align, nid,
                 &min_addr, &max_addr, (void *)_RET_IP_);

    ptr = memblock_alloc_internal(size, align, min_addr, max_addr, nid, false);
    if (ptr && size > 0)
        page_init_poison(ptr, size);

    return ptr;
}

/**
 * memblock_alloc_try_nid - allocate boot memory block
 *
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. This function zeroes the allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 *
 * allocates boot memory block 分配启动内存块
 */
void *__init memblock_alloc_try_nid(/* 分配启动 内存 块 */
                                    phys_addr_t size, phys_addr_t align, phys_addr_t min_addr, phys_addr_t max_addr,
                                    int nid)
{
    void *ptr;

    memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n", __func__, (u64)size, (u64)align, nid,
                 &min_addr, &max_addr, (void *)_RET_IP_);

    /**
     *
     */
    ptr = memblock_alloc_internal(size, align, min_addr, max_addr, nid, false);
    if (ptr)
        memset(ptr, 0, size);

    return ptr;
}

/**
 * __memblock_free_late - free pages directly to buddy allocator
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * This is only useful when the memblock allocator has already been torn
 * down, but we are still initializing the system.  Pages are released directly
 * to the buddy allocator.
 */
void __init __memblock_free_late(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t cursor, end;

    end = base + size - 1;
    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__, &base, &end, (void *)_RET_IP_);
    kmemleak_free_part_phys(base, size);
    cursor = PFN_UP(base);
    end = PFN_DOWN(base + size);

    for (; cursor < end; cursor++) {
        memblock_free_pages(pfn_to_page(cursor), cursor, 0);
        totalram_pages_inc();
    }
}

/*
 * Remaining API functions
 */

phys_addr_t __init_memblock memblock_phys_mem_size(void)
{
    return memblock.memory.total_size;
}

phys_addr_t __init_memblock memblock_reserved_size(void)
{
    return memblock.reserved.total_size;
}

/* lowest address */
phys_addr_t __init_memblock memblock_start_of_DRAM(void)
{
    return memblock.memory.regions[0].base;
}

/**
 *  DRAM 的终止 物理地址
 */
phys_addr_t __init_memblock memblock_end_of_DRAM(void)
{
    int idx = memblock.memory.cnt - 1;

    return (memblock.memory.regions[idx].base + memblock.memory.regions[idx].size);
}

static phys_addr_t __init_memblock __find_max_addr(phys_addr_t limit)
{
    phys_addr_t max_addr = PHYS_ADDR_MAX;
    struct memblock_region *r;

    /*
	 * translate the memory @limit size into the max address within one of
	 * the memory memblock regions, if the @limit exceeds the total size
	 * of those regions, max_addr will keep original value PHYS_ADDR_MAX
	 */
    for_each_mem_region(r)
    {
        if (limit <= r->size) {
            max_addr = r->base + limit;
            break;
        }
        limit -= r->size;
    }

    return max_addr;
}

void __init memblock_enforce_memory_limit(phys_addr_t limit)
{
    phys_addr_t max_addr;

    if (!limit)
        return;

    max_addr = __find_max_addr(limit);

    /* @limit exceeds the total size of the memory, do nothing */
    if (max_addr == PHYS_ADDR_MAX)
        return;

    /* truncate both memory and reserved regions */
    memblock_remove_range(&memblock.memory, max_addr, PHYS_ADDR_MAX);
    memblock_remove_range(&memblock.reserved, max_addr, PHYS_ADDR_MAX);
}

void __init memblock_cap_memory_range(phys_addr_t base, phys_addr_t size)
{
    int start_rgn, end_rgn;
    int i, ret;

    if (!size)
        return;

    ret = memblock_isolate_range(&memblock.memory, base, size, &start_rgn, &end_rgn);
    if (ret)
        return;

    /* remove all the MAP regions */
    for (i = memblock.memory.cnt - 1; i >= end_rgn; i--)
        if (!memblock_is_nomap(&memblock.memory.regions[i]))
            memblock_remove_region(&memblock.memory, i);

    for (i = start_rgn - 1; i >= 0; i--)
        if (!memblock_is_nomap(&memblock.memory.regions[i]))
            memblock_remove_region(&memblock.memory, i);

    /* truncate the reserved regions */
    memblock_remove_range(&memblock.reserved, 0, base);
    memblock_remove_range(&memblock.reserved, base + size, PHYS_ADDR_MAX);
}

void __init memblock_mem_limit_remove_map(phys_addr_t limit)
{
    phys_addr_t max_addr;

    if (!limit)
        return;

    max_addr = __find_max_addr(limit);

    /* @limit exceeds the total size of the memory, do nothing */
    if (max_addr == PHYS_ADDR_MAX)
        return;

    memblock_cap_memory_range(0, max_addr);
}

static int __init_memblock memblock_search(struct memblock_type *type, phys_addr_t addr)
{
    unsigned int left = 0, right = type->cnt;

    do {
        unsigned int mid = (right + left) / 2;

        if (addr < type->regions[mid].base)
            right = mid;
        else if (addr >= (type->regions[mid].base + type->regions[mid].size))
            left = mid + 1;
        else
            return mid;
    } while (left < right);
    return -1;
}

bool __init_memblock memblock_is_reserved(phys_addr_t addr)
{
    return memblock_search(&memblock.reserved, addr) != -1;
}

bool __init_memblock memblock_is_memory(phys_addr_t addr)
{
    return memblock_search(&memblock.memory, addr) != -1;
}

bool __init_memblock memblock_is_map_memory(phys_addr_t addr)
{
    int i = memblock_search(&memblock.memory, addr);

    if (i == -1)
        return false;
    return !memblock_is_nomap(&memblock.memory.regions[i]);
}

int __init_memblock memblock_search_pfn_nid(unsigned long pfn, unsigned long *start_pfn, unsigned long *end_pfn)
{
    struct memblock_type *type = &memblock.memory;
    int mid = memblock_search(type, PFN_PHYS(pfn));

    if (mid == -1)
        return -1;

    *start_pfn = PFN_DOWN(type->regions[mid].base);
    *end_pfn = PFN_DOWN(type->regions[mid].base + type->regions[mid].size);

    return memblock_get_region_node(&type->regions[mid]);
}

/**
 * memblock_is_region_memory - check if a region is a subset of memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base + @size) is a subset of a memory block.
 *
 * Return:
 * 0 if false, non-zero if true
 */
bool __init_memblock memblock_is_region_memory(phys_addr_t base, phys_addr_t size)
{
    int idx = memblock_search(&memblock.memory, base);
    phys_addr_t end = base + memblock_cap_size(base, &size);

    if (idx == -1)
        return false;
    return (memblock.memory.regions[idx].base + memblock.memory.regions[idx].size) >= end;
}

/**
 * memblock_is_region_reserved - check if a region intersects reserved memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base + @size) intersects a reserved
 * memory block.
 *
 * Return:
 * True if they intersect, false if not.
 */
bool __init_memblock memblock_is_region_reserved(phys_addr_t base, phys_addr_t size)
{
    memblock_cap_size(base, &size);
    return memblock_overlaps_region(&memblock.reserved, base, size);
}

/**
 *
 */
void __init_memblock memblock_trim_memory(phys_addr_t align)
{
    phys_addr_t start, end, orig_start, orig_end;
    struct memblock_region *r;

    /**
     *  遍历 memblock.memory
     */
    for_each_mem_region(r)
    {
        orig_start = r->base;
        orig_end = r->base + r->size;

        /**
         *  region 范围
         */
        start = round_up(orig_start, align);
        end = round_down(orig_end, align);

        if (start == orig_start && end == orig_end)
            continue;

        /**
         *  地址合理，更新一下
         */
        if (start < end) {
            r->base = start;
            r->size = end - start;

        } else {
            /**
             *  地址不合理，直接释放
             */
            memblock_remove_region(&memblock.memory, r - memblock.memory.regions);
            r--;
        }
    }
}

/**
 *  为 `memblock` 分配内存设置一个界限
 *  这个界限可以是 `ISA_END_ADDRESS` 或者 `0x100000`
 */
void __init_memblock memblock_set_current_limit(phys_addr_t limit)
{
    memblock.current_limit = limit;
}

phys_addr_t __init_memblock memblock_get_current_limit(void)
{
    return memblock.current_limit;
}

/**
 *  显示
 */
static void __init_memblock memblock_dump(struct memblock_type *type)
{
    phys_addr_t base, end, size;
    enum memblock_flags flags;
    int idx;
    struct memblock_region *rgn;

    pr_info(" %s.cnt  = 0x%lx\n", type->name, type->cnt);

    /**
     *  遍历 memblock.memory 或 memblock.reserved
     */
    for_each_memblock_type(idx, type, rgn)
    {
        char nid_buf[32] = "";

        base = rgn->base;
        size = rgn->size;
        end = base + size - 1;
        flags = rgn->flags;

#ifdef CONFIG_NEED_MULTIPLE_NODES
        if (memblock_get_region_node(rgn) != MAX_NUMNODES)
            snprintf(nid_buf, sizeof(nid_buf), " on node %d", memblock_get_region_node(rgn));
#endif
        pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n", type->name, idx, &base, &end, &size, nid_buf, flags);
    }
}

/**
 *  显示memblock
 */
static void __init_memblock __memblock_dump_all(void)
{
    pr_info("MEMBLOCK configuration:\n");
    pr_info(" memory size = %pa reserved size = %pa\n", &memblock.memory.total_size, &memblock.reserved.total_size);

    /**
     *  memory 和 reserved
     */
    memblock_dump(&memblock.memory);
    memblock_dump(&memblock.reserved);

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
//	memblock_dump(&physmem);
#endif
}

/**
 *  显示 memblock 内容
 */
void __init_memblock memblock_dump_all(void)
{
    if (memblock_debug)
        __memblock_dump_all();
}

void __init memblock_allow_resize(void)
{
    memblock_can_resize = 1;
}

static int __init early_memblock(char *p)
{
    if (p && strstr(p, "debug"))
        memblock_debug = 1;
    return 0;
}
early_param("memblock", early_memblock);

/**
 *
 */
static void __init __free_pages_memory(unsigned long start, unsigned long end) /* 释放 页 内存 */
{
    int order;

    while (start < end) {
        order = min(MAX_ORDER /* 11 */ - 1UL, __ffs(start) /* 第一个 bit */);

        while (start + (1UL << order) > end)
            order--;

        /**
         *  从 memblock 中释放 page
         */
        memblock_free_pages(pfn_to_page(start) /* 页帧号 到 page */, start, order);

        start += (1UL << order);
    }
}

/**
 *
 */
static unsigned long __init __free_memory_core(phys_addr_t start, /* 从 start 到 end 有多少 pages */
                                               phys_addr_t end)
{
    unsigned long start_pfn = PFN_UP(start);
    unsigned long end_pfn = min_t(unsigned long, PFN_DOWN(end), max_low_pfn);

    if (start_pfn >= end_pfn)
        return 0;

    __free_pages_memory(start_pfn, end_pfn);

    return end_pfn - start_pfn;
}

/**
  * 释放低端内存并返回释放的页面数量
  */
static unsigned long __init free_low_memory_core_early(void)
{
    unsigned long count = 0;
    phys_addr_t start, end;
    u64 i;

    memblock_clear_hotplug(0, -1);

    /* 遍历 memblock.reserved */
    for_each_reserved_mem_range(i, &start, &end)
    {
        /**
         *  初始化 每个 page
         */
        reserve_bootmem_region(start, end);
    }

    /*
	 * We need to use NUMA_NO_NODE instead of NODE_DATA(0)->node_id
	 *  because in some case like Node0 doesn't have RAM installed
	 *  low ram will be on Node1
	 */
    for_each_free_mem_range(i, NUMA_NO_NODE, MEMBLOCK_NONE, &start, &end, NULL)
    {
        /**
         *
         */
        count += __free_memory_core(start, end); /* 计算总页数 */
    }

    return count;
}

static int __initdata reset_managed_pages_done;

/**
 *  所有 zone 管理 页  置零
 */
void reset_node_managed_pages(pg_data_t *pgdat)
{
    struct zone *z;
    /**
     *  遍历 node 中所有zone
     */
    for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
        atomic_long_set(&z->managed_pages, 0); /* 伙伴系统管理的页数量清零 */
}

/**
	函数首先检查 reset_managed_pages_done 标志。如果已经完成重置，则直接返回，避免重复操作。

	使用 for_each_online_pgdat 宏遍历所有在线的内存节点（NUMA 节点）。

	对于每个节点，调用 reset_node_managed_pages(pgdat) 函数来重置该节点的所有区域的管理页面计数。

	重置完成后，将 reset_managed_pages_done 标志设置为 1，表示重置操作已完成
 */
void __init reset_all_zones_managed_pages(void) /* 重置所有的 ZONE 管理页 */
{
    struct pglist_data *pgdat;

    if (reset_managed_pages_done)
        return;

    /**
     *  遍历所有 NODE
     */
    for_each_online_pgdat(pgdat)
    { /* 遍历 每个在线 的 页表 */

        /**
         *  重置NODE管理页
         */
        reset_node_managed_pages(pgdat);
    }

    reset_managed_pages_done = 1;
}

/**
 * memblock_free_all - release free pages to the buddy allocator
 *
 * Return: the number of pages actually released.
 *
 * 释放空闲页 给 伙伴系统 分配器
 */
unsigned long __init memblock_free_all(void) /* 所有内存块都挂入 freelists 中 */
{
    unsigned long pages;

    //设置当前结点的所有zone.managed_pages = 0
    reset_all_zones_managed_pages(); /* 重置所有 的 ZONE 管理页 - 伙伴系统管理的页 清零 */

    /**
     *  释放 memblock 到伙伴系统
     */
    pages = free_low_memory_core_early(); /* 获取所有RAM 页 个数 */

    /**
     *  ram 总  page 数量
     */
    totalram_pages_add(pages); /* 添加至 RAM原子变量 */

    return pages;
}

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_ARCH_KEEP_MEMBLOCK)

static int memblock_debug_show(struct seq_file *m, void *private)
{
    struct memblock_type *type = m->private;
    struct memblock_region *reg;
    int i;
    phys_addr_t end;

    for (i = 0; i < type->cnt; i++) {
        reg = &type->regions[i];
        end = reg->base + reg->size - 1;

        seq_printf(m, "%4d: ", i);
        seq_printf(m, "%pa..%pa\n", &reg->base, &end);
    }
    return 0;
}
DEFINE_SHOW_ATTRIBUTE(memblock_debug);

static int __init memblock_init_debugfs(void)
{
    struct dentry *root = debugfs_create_dir("memblock", NULL);

    debugfs_create_file("memory", 0444, root, &memblock.memory, &memblock_debug_fops);
    debugfs_create_file("reserved", 0444, root, &memblock.reserved, &memblock_debug_fops);
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
    debugfs_create_file("physmem", 0444, root, &physmem, &memblock_debug_fops);
#endif

    return 0;
}
__initcall(memblock_init_debugfs);

#endif /* CONFIG_DEBUG_FS */
