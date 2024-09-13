// SPDX-License-Identifier: GPL-2.0-only
/*
 * Low level x86 E820 memory map handling functions.
 *
 * The firmware and bootloader passes us the "E820 table", which is the primary
 * physical memory layout description available about x86 systems.
 *
 * The kernel takes the E820 memory layout and optionally modifies it with
 * quirks and other tweaks, and feeds that into the generic Linux memory
 * allocation code routines via a platform independent interface (memblock, etc.).
 */
#include <linux/crash_dump.h>
#include <linux/memblock.h>
#include <linux/suspend.h>
#include <linux/acpi.h>
#include <linux/firmware-map.h>
#include <linux/sort.h>
#include <linux/memory_hotplug.h>

#include <asm/e820/api.h>
#include <asm/setup.h>

/*
 * We organize the E820 table into three main data structures:
 *
 * - 'e820_table_firmware': the original firmware version passed to us by the
 *   bootloader - not modified by the kernel. It is composed of two parts:
 *   the first 128 E820 memory entries in boot_params.e820_table and the remaining
 *   (if any) entries of the SETUP_E820_EXT nodes. We use this to:
 *
 *       - inform the user about the firmware's notion of memory layout
 *         via /sys/firmware/memmap
 *
 *       - the hibernation code uses it to generate a kernel-independent MD5
 *         fingerprint of the physical memory layout of a system.
 *
 * - 'e820_table_kexec': a slightly modified (by the kernel) firmware version
 *   passed to us by the bootloader - the major difference between
 *   e820_table_firmware[] and this one is that, the latter marks the setup_data
 *   list created by the EFI boot stub as reserved, so that kexec can reuse the
 *   setup_data information in the second kernel. Besides, e820_table_kexec[]
 *   might also be modified by the kexec itself to fake a mptable.
 *   We use this to:
 *
 *       - kexec, which is a bootloader in disguise, uses the original E820
 *         layout to pass to the kexec-ed kernel. This way the original kernel
 *         can have a restricted E820 map while the kexec()-ed kexec-kernel
 *         can have access to full memory - etc.
 *
 * - 'e820_table': this is the main E820 table that is massaged by the
 *   low level x86 platform code, or modified by boot parameters, before
 *   passed on to higher level MM layers.
 *
 * Once the E820 map has been converted to the standard Linux memory layout
 * information its role stops - modifying it has no effect and does not get
 * re-propagated. So itsmain role is a temporary bootstrap storage of firmware
 * specific memory layout data during early bootup.
 */

//e820是和BIOS的一个中断相关的，具体说是int 0x15。之所以叫e820是因为在用这个中断时ax必须是0xe820。
//这个中断的作用是得到系统的内存布局。
//因为系统内存会有很多段，每段的类型属性也不一样，所以这个查询是“迭代式”的，每次求得一个段。

static struct e820_table __initdata e820_table_init		;
static struct e820_table __initdata e820_table_kexec_init		;
static struct e820_table __initdata e820_table_firmware_init	;

/*
 * The whole array of E820 entries:
 *
 * [    0.000000] e820: BIOS-provided physical RAM map:
 * [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
 * [    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
 * [    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
 * [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bff7ffff] usable
 * [    0.000000] BIOS-e820: [mem 0x00000000bff80000-0x00000000bfffffff] reserved
 * [    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved
 * [    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
 * [    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000023fffffff] usable
 */
struct e820_table __refdata *e820_table 			= &e820_table_init;
struct e820_table __refdata *e820_table_kexec 		= &e820_table_kexec_init;
struct e820_table __refdata *e820_table_firmware 	= &e820_table_firmware_init;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0xaeedbabe;

#ifdef CONFIG_PCI
EXPORT_SYMBOL(pci_mem_start);
#endif

/*
 * This function checks if any part of the range <start,end> is mapped
 * with type.
 */
static bool _e820__mapped_any(struct e820_table *table,
			      u64 start, u64 end, enum e820_type type)
{
	int i;

	for (i = 0; i < table->nr_entries; i++) {
		struct e820_entry *entry = &table->entries[i];

		if (type && entry->type != type)
			continue;
		if (entry->addr >= end || entry->addr + entry->size <= start)
			continue;
		return true;
	}
	return false;
}

bool e820__mapped_raw_any(u64 start, u64 end, enum e820_type type)
{
	return _e820__mapped_any(e820_table_firmware, start, end, type);
}
EXPORT_SYMBOL_GPL(e820__mapped_raw_any);

bool e820__mapped_any(u64 start, u64 end, enum e820_type type)
{
	return _e820__mapped_any(e820_table, start, end, type);
}
EXPORT_SYMBOL_GPL(e820__mapped_any);

/*
 * This function checks if the entire <start,end> range is mapped with 'type'.
 *
 * Note: this function only works correctly once the E820 table is sorted and
 * not-overlapping (at least for the range specified), which is the case normally.
 */
static struct e820_entry *__e820__mapped_all(u64 start, u64 end, enum e820_type type)
{
	int i;

    /**
     *  遍历整个 table *
     *  Physic Memory
     *
     *  |<--16MB-->|<----------64MB--------->|     |<----reserved--->|<----RAM---->|<-----ACPI----->|
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  |          |                         |     |                 |             |                |
     *  |          |                         | ... |                 |             |                |
     *  |          |                         |     |                 |             |                |
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  ^          ^                               ^                 ^             ^
     *  |          |                               |                 |             |
     *  | +--------+                               |                 |             |
     *  | |     +----------------------------------+                 |             |
     *  | |     | +--------------------------------------------------+             |
     *  | |     | | +--------------------------------------------------------------+
     *  | |     | | |
     *  | |     | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     * | | |   | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | |   | | | | | | | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     *      e820_table
     */
	for (i = 0; i < e820_table->nr_entries; i++) {

        /**
         *
         */
		struct e820_entry *entry = &e820_table->entries[i];

		if (type && entry->type != type)
			continue;

		/* Is the region (part) in overlap with the current region? */
		if (entry->addr >= end || entry->addr + entry->size <= start)
			continue;

		/*
		 * If the region is at the beginning of <start,end> we move
		 * 'start' to the end of the region since it's ok until there
		 *
		 * 写小了，给他扩大
		 */
		if (entry->addr <= start)
			start = entry->addr + entry->size;

		/*
		 * If 'start' is now at or beyond 'end', we're done, full
		 * coverage of the desired range exists:
		 */
		if (start >= end)
			return entry;
	}

	return NULL;
}

/*
 * This function checks if the entire range <start,end> is mapped with type.
 */
bool __init e820__mapped_all(u64 start, u64 end, enum e820_type type)
{
    /**
     *  映射
     */
	return __e820__mapped_all(start, end, type);
}

/*
 * This function returns the type associated with the range <start,end>.
 */
int e820__get_entry_type(u64 start, u64 end)
{
	struct e820_entry *entry = __e820__mapped_all(start, end, 0);

	return entry ? entry->type : -EINVAL;
}

/*
 * Add a memory region to the kernel E820 map.
 */
static void __init __e820__range_add(struct e820_table *table, u64 start, u64 size, enum e820_type type)
{
	int x = table->nr_entries;

	if (x >= ARRAY_SIZE(table->entries)) {
		pr_err("too many entries; ignoring [mem %#010llx-%#010llx]\n",
		       start, start + size - 1);
		return;
	}

    /**
     *  添加 到 e820_table
     */
	table->entries[x].addr = start;
	table->entries[x].size = size;
	table->entries[x].type = type;
	table->nr_entries++;
}

/**
 *  添加一块内存到 e820 中
 */
void __init e820__range_add(u64 start, u64 size, enum e820_type type)
{
    /**
     *  添加
     */
	__e820__range_add(e820_table, start, size, type);
}

static void __init e820_print_type(enum e820_type type)
{
	switch (type) {
	case E820_TYPE_RAM:		/* Fall through: */
	case E820_TYPE_RESERVED_KERN:	pr_cont("usable");			break;
	case E820_TYPE_RESERVED:	pr_cont("reserved");			break;
	case E820_TYPE_SOFT_RESERVED:	pr_cont("soft reserved");		break;
	case E820_TYPE_ACPI:		pr_cont("ACPI data");			break;
	case E820_TYPE_NVS:		pr_cont("ACPI NVS");			break;
	case E820_TYPE_UNUSABLE:	pr_cont("unusable");			break;
	case E820_TYPE_PMEM:		/* Fall through: */
	case E820_TYPE_PRAM:		pr_cont("persistent (type %u)", type);	break;
	default:			pr_cont("type %u", type);		break;
	}
}

/**
 *  打印BIOS 的 内存布局
 */
void __init e820__print_table(char *who)
{
    //$ dmesg | grep e820
    //[    0.000000] e820: BIOS-provided physical RAM map:
    //[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
    //[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bff7ffff] usable
    //[    0.000000] BIOS-e820: [mem 0x00000000bff80000-0x00000000bfffffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000023fffffff] usable

	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		pr_info("%s: [mem %#018Lx-%#018Lx] ",
			who,
			e820_table->entries[i].addr,
			e820_table->entries[i].addr + e820_table->entries[i].size - 1);

		e820_print_type(e820_table->entries[i].type);
		pr_cont("\n");
	}
}

/*
 * Sanitize an E820 map.
 *
 * Some E820 layouts include overlapping entries. The following
 * replaces the original E820 map with a new one, removing overlaps,
 * and resolving conflicting memory types in favor of highest
 * numbered type.
 *
 * The input parameter 'entries' points to an array of 'struct
 * e820_entry' which on entry has elements in the range [0, *nr_entries)
 * valid, and which has space for up to max_nr_entries entries.
 * On return, the resulting sanitized E820 map entries will be in
 * overwritten in the same location, starting at 'entries'.
 *
 * The integer pointed to by nr_entries must be valid on entry (the
 * current number of valid entries located at 'entries'). If the
 * sanitizing succeeds the *nr_entries will be updated with the new
 * number of valid entries (something no more than max_nr_entries).
 *
 * The return value from e820__update_table() is zero if it
 * successfully 'sanitized' the map entries passed in, and is -1
 * if it did nothing, which can happen if either of (1) it was
 * only passed one map entry, or (2) any of the input map entries
 * were invalid (start + size < start, meaning that the size was
 * so big the described memory range wrapped around through zero.)
 *
 *	Visually we're performing the following
 *	(1,2,3,4 = memory types)...
 *
 *	Sample memory map (w/overlaps):
 *	   ____22__________________
 *	   ______________________4_
 *	   ____1111________________
 *	   _44_____________________
 *	   11111111________________
 *	   ____________________33__
 *	   ___________44___________
 *	   __________33333_________
 *	   ______________22________
 *	   ___________________2222_
 *	   _________111111111______
 *	   _____________________11_
 *	   _________________4______
 *
 *	Sanitized equivalent (no overlap):
 *	   1_______________________
 *	   _44_____________________
 *	   ___1____________________
 *	   ____22__________________
 *	   ______11________________
 *	   _________1______________
 *	   __________3_____________
 *	   ___________44___________
 *	   _____________33_________
 *	   _______________2________
 *	   ________________1_______
 *	   _________________4______
 *	   ___________________2____
 *	   ____________________33__
 *	   ______________________4_
 */
struct change_member {
	/* Pointer to the original entry: */
	struct e820_entry	*entry;
	/* Address for this change point: */
	unsigned long long	addr;
};

static struct change_member	__initdata change_point_list[2*E820_MAX_ENTRIES]	;
static struct change_member	__initdata *change_point[2*E820_MAX_ENTRIES]	;
static struct e820_entry	__initdata *overlap_list[E820_MAX_ENTRIES]		;
static struct e820_entry	__initdata new_entries[E820_MAX_ENTRIES]		;

/**
 *
 */
static int __init cpcompare(const void *a, const void *b)
{
	struct change_member * const *app = a, * const *bpp = b;
	const struct change_member *ap = *app, *bp = *bpp;

	/*
	 * Inputs are pointers to two elements of change_point[].  If their
	 * addresses are not equal, their difference dominates.  If the addresses
	 * are equal, then consider one that represents the end of its region
	 * to be greater than one that does not.
	 */
	if (ap->addr != bp->addr)
		return ap->addr > bp->addr ? 1 : -1;

	return (ap->addr != ap->entry->addr) - (bp->addr != bp->entry->addr);
}

static bool e820_nomerge(enum e820_type type)
{
	/*
	 * These types may indicate distinct platform ranges aligned to
	 * numa node, protection domain, performance domain, or other
	 * boundaries. Do not merge them.
	 */
	if (type == E820_TYPE_PRAM)
		return true;
	if (type == E820_TYPE_SOFT_RESERVED)
		return true;
	return false;
}

/**
 *
 */
int __init e820__update_table(struct e820_table *table)
{
	struct e820_entry *entries = table->entries;
	u32 max_nr_entries = ARRAY_SIZE(table->entries);
	enum e820_type current_type, last_type;
	unsigned long long last_addr;
	u32 new_nr_entries, overlap_entries;
	u32 i, chg_idx, chg_nr;

	/* If there's only one memory region, don't bother: */
	if (table->nr_entries < 2)
		return -1;

	BUG_ON(table->nr_entries > max_nr_entries);

    /**
     *  检查
     */
	/* Bail out if we find any unreasonable addresses in the map: */
	for (i = 0; i < table->nr_entries; i++) {
		if (entries[i].addr + entries[i].size < entries[i].addr)
			return -1;
	}

	/* Create pointers for initial change-point information (for sorting): */
	for (i = 0; i < 2 * table->nr_entries; i++)
		change_point[i] = &change_point_list[i];

	/*
	 * Record all known change-points (starting and ending addresses),
	 * omitting empty memory regions:
	 */
	chg_idx = 0;
	for (i = 0; i < table->nr_entries; i++)	{
		if (entries[i].size != 0) {
			change_point[chg_idx]->addr	= entries[i].addr;
			change_point[chg_idx++]->entry	= &entries[i];
			change_point[chg_idx]->addr	= entries[i].addr + entries[i].size;
			change_point[chg_idx++]->entry	= &entries[i];
		}
	}
	chg_nr = chg_idx;

	/* Sort change-point list by memory addresses (low -> high): */
	sort(change_point, chg_nr, sizeof(*change_point), cpcompare, NULL);

	/* Create a new memory map, removing overlaps: */
	overlap_entries = 0;	 /* Number of entries in the overlap table */
	new_nr_entries = 0;	 /* Index for creating new map entries */
	last_type = 0;		 /* Start with undefined memory type */
	last_addr = 0;		 /* Start with 0 as last starting address */

    /**
     *
     */
	/* Loop through change-points, determining effect on the new map: */
	for (chg_idx = 0; chg_idx < chg_nr; chg_idx++) {
		/* Keep track of all overlapping entries */
		if (change_point[chg_idx]->addr == change_point[chg_idx]->entry->addr) {
			/* Add map entry to overlap list (> 1 entry implies an overlap) */
			overlap_list[overlap_entries++] = change_point[chg_idx]->entry;
		} else {
			/* Remove entry from list (order independent, so swap with last): */
			for (i = 0; i < overlap_entries; i++) {
				if (overlap_list[i] == change_point[chg_idx]->entry)
					overlap_list[i] = overlap_list[overlap_entries-1];
			}
			overlap_entries--;
		}
		/*
		 * If there are overlapping entries, decide which
		 * "type" to use (larger value takes precedence --
		 * 1=usable, 2,3,4,4+=unusable)
		 */
		current_type = 0;
		for (i = 0; i < overlap_entries; i++) {
			if (overlap_list[i]->type > current_type)
				current_type = overlap_list[i]->type;
		}

		/* Continue building up new map based on this information: */
		if (current_type != last_type || e820_nomerge(current_type)) {
			if (last_type != 0)	 {
				new_entries[new_nr_entries].size = change_point[chg_idx]->addr - last_addr;
				/* Move forward only if the new size was non-zero: */
				if (new_entries[new_nr_entries].size != 0)
					/* No more space left for new entries? */
					if (++new_nr_entries >= max_nr_entries)
						break;
			}
			if (current_type != 0)	{
				new_entries[new_nr_entries].addr = change_point[chg_idx]->addr;
				new_entries[new_nr_entries].type = current_type;
				last_addr = change_point[chg_idx]->addr;
			}
			last_type = current_type;
		}
	}

	/* Copy the new entries into the original location: */
	memcpy(entries, new_entries, new_nr_entries*sizeof(*entries));
	table->nr_entries = new_nr_entries;

	return 0;
}

/**
 * 拷贝 BIOS E820 到一个安全的地方
 */
static int __init __append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	struct boot_e820_entry *entry = entries;

    /**
     *  遍历 e820 table
     */
	while (nr_entries) {

        /**
         *  获取这个内存块的描述
         */
		u64 start = entry->addr;
		u64 size = entry->size;
		u64 end = start + size - 1;
		u32 type = entry->type;

		/* Ignore the entry on 64-bit overflow: */
		if (start > end && likely(size))
			return -1;

        /**
         *  添加 到 e820_table 全局变量中
         */
		e820__range_add(start, size, type);

		entry++;
		nr_entries--;
	}
	return 0;
}

/*
 * Copy the BIOS E820 map into a safe place.
 *
 * Sanity-check it while we're at it..
 *
 * If we're lucky and live on a modern system, the setup code
 * will have given us a memory map that we can use to properly
 * set up memory.  If we aren't, we'll fake a memory map.
 *
 * 拷贝 BIOS E820 到一个安全的地方
 */
static int __init append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	/* Only one memory region (or negative)? Ignore it */
	if (nr_entries < 2)
		return -1;

    /**
     *  成功返回 0
     */
	return __append_e820_table(entries, nr_entries);
}

static u64 __init
__e820__range_update(struct e820_table *table, u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	u64 end;
	unsigned int i;
	u64 real_updated_size = 0;

	BUG_ON(old_type == new_type);

	if (size > (ULLONG_MAX - start))
		size = ULLONG_MAX - start;

	end = start + size;
	printk(KERN_DEBUG "e820: update [mem %#010Lx-%#010Lx] ", start, end - 1);
	e820_print_type(old_type);
	pr_cont(" ==> ");
	e820_print_type(new_type);
	pr_cont("\n");

	for (i = 0; i < table->nr_entries; i++) {
		struct e820_entry *entry = &table->entries[i];
		u64 final_start, final_end;
		u64 entry_end;

		if (entry->type != old_type)
			continue;

		entry_end = entry->addr + entry->size;

		/* Completely covered by new range? */
		if (entry->addr >= start && entry_end <= end) {
			entry->type = new_type;
			real_updated_size += entry->size;
			continue;
		}

		/* New range is completely covered? */
		if (entry->addr < start && entry_end > end) {
			__e820__range_add(table, start, size, new_type);
			__e820__range_add(table, end, entry_end - end, entry->type);
			entry->size = start - entry->addr;
			real_updated_size += size;
			continue;
		}

		/* Partially covered: */
		final_start = max(start, entry->addr);
		final_end = min(end, entry_end);
		if (final_start >= final_end)
			continue;

		__e820__range_add(table, final_start, final_end - final_start, new_type);

		real_updated_size += final_end - final_start;

		/*
		 * Left range could be head or tail, so need to update
		 * its size first:
		 */
		entry->size -= final_end - final_start;
		if (entry->addr < final_start)
			continue;

		entry->addr = final_end;
	}
	return real_updated_size;
}

u64 __init e820__range_update(u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	return __e820__range_update(e820_table, start, size, old_type, new_type);
}

static u64 __init e820__range_update_kexec(u64 start, u64 size, enum e820_type old_type, enum e820_type  new_type)
{
	return __e820__range_update(e820_table_kexec, start, size, old_type, new_type);
}

/* Remove a range of memory from the E820 table: */
u64 __init e820__range_remove(u64 start, u64 size, enum e820_type old_type, bool check_type)
{
	int i;
	u64 end;
	u64 real_removed_size = 0;

	if (size > (ULLONG_MAX - start))
		size = ULLONG_MAX - start;

	end = start + size;
	printk(KERN_DEBUG "e820: remove [mem %#010Lx-%#010Lx] ", start, end - 1);
	if (check_type)
		e820_print_type(old_type);
	pr_cont("\n");

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 final_start, final_end;
		u64 entry_end;

		if (check_type && entry->type != old_type)
			continue;

		entry_end = entry->addr + entry->size;

		/* Completely covered? */
		if (entry->addr >= start && entry_end <= end) {
			real_removed_size += entry->size;
			memset(entry, 0, sizeof(*entry));
			continue;
		}

		/* Is the new range completely covered? */
		if (entry->addr < start && entry_end > end) {
			e820__range_add(end, entry_end - end, entry->type);
			entry->size = start - entry->addr;
			real_removed_size += size;
			continue;
		}

		/* Partially covered: */
		final_start = max(start, entry->addr);
		final_end = min(end, entry_end);
		if (final_start >= final_end)
			continue;

		real_removed_size += final_end - final_start;

		/*
		 * Left range could be head or tail, so need to update
		 * the size first:
		 */
		entry->size -= final_end - final_start;
		if (entry->addr < final_start)
			continue;

		entry->addr = final_end;
	}
	return real_removed_size;
}

void __init e820__update_table_print(void)
{
	if (e820__update_table(e820_table))
		return;

	pr_info("modified physical RAM map:\n");
	e820__print_table("modified");
}

static void __init e820__update_table_kexec(void)
{
	e820__update_table(e820_table_kexec);
}

#define MAX_GAP_END 0x100000000ull

/*
 * Search for a gap in the E820 memory space from 0 to MAX_GAP_END (4GB).
 */
static int __init e820_search_gap(unsigned long *gapstart, unsigned long *gapsize)
{
	unsigned long long last = MAX_GAP_END;
	int i = e820_table->nr_entries;
	int found = 0;

	while (--i >= 0) {
		unsigned long long start = e820_table->entries[i].addr;
		unsigned long long end = start + e820_table->entries[i].size;

		/*
		 * Since "last" is at most 4GB, we know we'll
		 * fit in 32 bits if this condition is true:
		 */
		if (last > end) {
			unsigned long gap = last - end;

			if (gap >= *gapsize) {
				*gapsize = gap;
				*gapstart = end;
				found = 1;
			}
		}
		if (start < last)
			last = start;
	}
	return found;
}

/*
 * Search for the biggest gap in the low 32 bits of the E820
 * memory space. We pass this space to the PCI subsystem, so
 * that it can assign MMIO resources for hotplug or
 * unconfigured devices in.
 *
 * Hopefully the BIOS let enough space left.
 */
__init void e820__setup_pci_gap(void)
{
	unsigned long gapstart, gapsize;
	int found;

	gapsize = 0x400000;
	found  = e820_search_gap(&gapstart, &gapsize);

	if (!found) {
#ifdef CONFIG_X86_64
		gapstart = (max_pfn << PAGE_SHIFT) + 1024*1024;
		pr_err("Cannot find an available gap in the 32-bit address range\n");
		pr_err("PCI devices with unassigned 32-bit BARs may not work!\n");
#else
		gapstart = 0x10000000;
#endif
	}

	/*
	 * e820__reserve_resources_late() protects stolen RAM already:
	 */
	pci_mem_start = gapstart;

	pr_info("[mem %#010lx-%#010lx] available for PCI devices\n",
		gapstart, gapstart + gapsize - 1);
}

/*
 * Called late during init, in free_initmem().
 *
 * Initial e820_table and e820_table_kexec are largish __initdata arrays.
 *
 * Copy them to a (usually much smaller) dynamically allocated area that is
 * sized precisely after the number of e820 entries.
 *
 * This is done after we've performed all the fixes and tweaks to the tables.
 * All functions which modify them are __init functions, which won't exist
 * after free_initmem().
 */
__init void e820__reallocate_tables(void)
{
	struct e820_table *n;
	int size;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table->nr_entries;
	n = kmemdup(e820_table, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_kexec->nr_entries;
	n = kmemdup(e820_table_kexec, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table_kexec = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_firmware->nr_entries;
	n = kmemdup(e820_table_firmware, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table_firmware = n;
}

/*
 * Because of the small fixed size of struct boot_params, only the first
 * 128 E820 memory entries are passed to the kernel via boot_params.e820_table,
 * the remaining (if any) entries are passed via the SETUP_E820_EXT node of
 * struct setup_data, which is parsed here.
 */
void __init e820__memory_setup_extended(u64 phys_addr, u32 data_len)
{
    //e820是和BIOS的一个中断相关的，具体说是int 0x15。之所以叫e820是因为在用这个中断时ax必须是0xe820。
    //这个中断的作用是得到系统的内存布局。
    //因为系统内存会有很多段，每段的类型属性也不一样，所以这个查询是“迭代式”的，每次求得一个段。

	int entries;
	struct boot_e820_entry *extmap;
	struct setup_data *sdata;

	sdata = early_memremap(phys_addr, data_len);
	entries = sdata->len / sizeof(*extmap);
	extmap = (struct boot_e820_entry *)(sdata->data);

	__append_e820_table(extmap, entries);
	e820__update_table(e820_table);

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	early_memunmap(sdata, data_len);
	pr_info("extended physical RAM map:\n");
	e820__print_table("extended");
}

/*
 * Find the ranges of physical addresses that do not correspond to
 * E820 RAM areas and register the corresponding pages as 'nosave' for
 * hibernation (32-bit) or software suspend and suspend to RAM (64-bit).
 *
 * This function requires the E820 map to be sorted and without any
 * overlapping entries.
 */
void __init e820__register_nosave_regions(unsigned long limit_pfn)
{
	int i;
	unsigned long pfn = 0;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (pfn < PFN_UP(entry->addr))
			register_nosave_region(pfn, PFN_UP(entry->addr));

		pfn = PFN_DOWN(entry->addr + entry->size);

		if (entry->type != E820_TYPE_RAM && entry->type != E820_TYPE_RESERVED_KERN)
			register_nosave_region(PFN_UP(entry->addr), pfn);

		if (pfn >= limit_pfn)
			break;
	}
}

#ifdef CONFIG_ACPI
/*
 * Register ACPI NVS memory regions, so that we can save/restore them during
 * hibernation and the subsequent resume:
 */
static int __init e820__register_nvs_regions(void)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type == E820_TYPE_NVS)
			acpi_nvs_register(entry->addr, entry->size);
	}

	return 0;
}
core_initcall(e820__register_nvs_regions);
#endif

/*
 * Allocate the requested number of bytes with the requsted alignment
 * and return (the physical address) to the caller. Also register this
 * range in the 'kexec' E820 table as a reserved range.
 *
 * This allows kexec to fake a new mptable, as if it came from the real
 * system.
 */
u64 __init e820__memblock_alloc_reserved(u64 size, u64 align)
{
	u64 addr;

	addr = memblock_phys_alloc(size, align);
	if (addr) {
		e820__range_update_kexec(addr, size, E820_TYPE_RAM, E820_TYPE_RESERVED);
		pr_info("update e820_table_kexec for e820__memblock_alloc_reserved()\n");
		e820__update_table_kexec();
	}

	return addr;
}

#ifdef CONFIG_X86_32
//# ifdef CONFIG_X86_PAE
//#  define MAX_ARCH_PFN		(1ULL<<(36-PAGE_SHIFT))
//# else
//#  define MAX_ARCH_PFN		(1ULL<<(32-PAGE_SHIFT))
//# endif
#else /* CONFIG_X86_32 */
# define MAX_ARCH_PFN MAXMEM>>PAGE_SHIFT
#endif

/*
 * Find the highest page frame number we have available
 */
static unsigned long __init e820_end_pfn(unsigned long limit_pfn, enum e820_type type)
{
	int i;
	unsigned long last_pfn = 0;
	unsigned long max_arch_pfn = MAX_ARCH_PFN;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		unsigned long start_pfn;
		unsigned long end_pfn;

		if (entry->type != type)
			continue;

		start_pfn = entry->addr >> PAGE_SHIFT;
		end_pfn = (entry->addr + entry->size) >> PAGE_SHIFT;

		if (start_pfn >= limit_pfn)
			continue;

        /**
         *  找到
         */
		if (end_pfn > limit_pfn) {
			last_pfn = limit_pfn;
			break;
		}
		if (end_pfn > last_pfn)
			last_pfn = end_pfn;
	}

	if (last_pfn > max_arch_pfn)
		last_pfn = max_arch_pfn;

	pr_info("last_pfn = %#lx max_arch_pfn = %#lx\n", last_pfn, max_arch_pfn);
	return last_pfn;
}

/**
 *
 */
unsigned long __init e820__end_of_ram_pfn(void)
{
	return e820_end_pfn(MAX_ARCH_PFN, E820_TYPE_RAM);
}

unsigned long __init e820__end_of_low_ram_pfn(void)
{
	return e820_end_pfn(1UL << (32 - PAGE_SHIFT), E820_TYPE_RAM);
}

static void __init early_panic(char *msg)
{
	early_printk(msg);
	panic(msg);
}

static int __initdata userdef ;

/* The "mem=nopentium" boot option disables 4MB page tables on 32-bit kernels: */
static int __init parse_memopt(char *p)
{
	u64 mem_size;

	if (!p)
		return -EINVAL;

	if (!strcmp(p, "nopentium")) {
#ifdef CONFIG_X86_32
		setup_clear_cpu_cap(X86_FEATURE_PSE);
		return 0;
#else
		pr_warn("mem=nopentium ignored! (only supported on x86_32)\n");
		return -EINVAL;
#endif
	}

	userdef = 1;
	mem_size = memparse(p, &p);

	/* Don't remove all memory when getting "mem={invalid}" parameter: */
	if (mem_size == 0)
		return -EINVAL;

	e820__range_remove(mem_size, ULLONG_MAX - mem_size, E820_TYPE_RAM, 1);

#ifdef CONFIG_MEMORY_HOTPLUG
	max_mem_size = mem_size;
#endif

	return 0;
}
early_param("mem", parse_memopt);

static int __init parse_memmap_one(char *p)
{
	char *oldp;
	u64 start_at, mem_size;

	if (!p)
		return -EINVAL;

	if (!strncmp(p, "exactmap", 8)) {
		e820_table->nr_entries = 0;
		userdef = 1;
		return 0;
	}

	oldp = p;
	mem_size = memparse(p, &p);
	if (p == oldp)
		return -EINVAL;

	userdef = 1;
	if (*p == '@') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_RAM);
	} else if (*p == '#') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_ACPI);
	} else if (*p == '$') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_RESERVED);
	} else if (*p == '!') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_PRAM);
	} else if (*p == '%') {
		enum e820_type from = 0, to = 0;

		start_at = memparse(p + 1, &p);
		if (*p == '-')
			from = simple_strtoull(p + 1, &p, 0);
		if (*p == '+')
			to = simple_strtoull(p + 1, &p, 0);
		if (*p != '\0')
			return -EINVAL;
		if (from && to)
			e820__range_update(start_at, mem_size, from, to);
		else if (to)
			e820__range_add(start_at, mem_size, to);
		else if (from)
			e820__range_remove(start_at, mem_size, from, 1);
		else
			e820__range_remove(start_at, mem_size, 0, 0);
	} else {
		e820__range_remove(mem_size, ULLONG_MAX - mem_size, E820_TYPE_RAM, 1);
	}

	return *p == '\0' ? 0 : -EINVAL;
}

static int __init parse_memmap_opt(char *str)
{
	while (str) {
		char *k = strchr(str, ',');

		if (k)
			*k++ = 0;

		parse_memmap_one(str);
		str = k;
	}

	return 0;
}
early_param("memmap", parse_memmap_opt);

/*
 * Reserve all entries from the bootloader's extensible data nodes list,
 * because if present we are going to use it later on to fetch e820
 * entries from it:
 */
void __init e820__reserve_setup_data(void)
{
	struct setup_data *data;
	u64 pa_data;

	pa_data = boot_params.hdr.setup_data;
	if (!pa_data)
		return;

    /**
     *
     */
	while (pa_data) {
		data = early_memremap(pa_data, sizeof(*data));
		e820__range_update(pa_data, sizeof(*data)+data->len, E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);

		/*
		 * SETUP_EFI is supplied by kexec and does not need to be
		 * reserved.
		 */
		if (data->type != SETUP_EFI)
			e820__range_update_kexec(pa_data,
						 sizeof(*data) + data->len,
						 E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);

		if (data->type == SETUP_INDIRECT &&
		    ((struct setup_indirect *)data->data)->type != SETUP_INDIRECT) {
			e820__range_update(((struct setup_indirect *)data->data)->addr,
					   ((struct setup_indirect *)data->data)->len,
					   E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);
			e820__range_update_kexec(((struct setup_indirect *)data->data)->addr,
						 ((struct setup_indirect *)data->data)->len,
						 E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);
		}

		pa_data = data->next;
		early_memunmap(data, sizeof(*data));
	}

	e820__update_table(e820_table);
	e820__update_table(e820_table_kexec);

	pr_info("extended physical RAM map:\n");
	e820__print_table("reserve setup_data");
}

/*
 * Called after parse_early_param(), after early parameters (such as mem=)
 * have been processed, in which case we already have an E820 table filled in
 * via the parameter callback function(s), but it's not sorted and printed yet:
 */
void __init e820__finish_early_params(void)
{
	if (userdef) {
		if (e820__update_table(e820_table) < 0)
			early_panic("Invalid user supplied memory map");

		pr_info("user-defined physical RAM map:\n");
		e820__print_table("user");
	}
}

/**
 *
 */
static const char *__init e820_type_to_string(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		return "System RAM";
	case E820_TYPE_ACPI:		return "ACPI Tables";
	case E820_TYPE_NVS:		return "ACPI Non-volatile Storage";
	case E820_TYPE_UNUSABLE:	return "Unusable memory";
	case E820_TYPE_PRAM:		return "Persistent Memory (legacy)";
	case E820_TYPE_PMEM:		return "Persistent Memory";
	case E820_TYPE_RESERVED:	return "Reserved";
	case E820_TYPE_SOFT_RESERVED:	return "Soft Reserved";
	default:
	    return "Unknown E820 type";
	}
}

static unsigned long __init e820_type_to_iomem_type(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		return IORESOURCE_SYSTEM_RAM;
	case E820_TYPE_ACPI:		/* Fall-through: */
	case E820_TYPE_NVS:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	case E820_TYPE_PRAM:		/* Fall-through: */
	case E820_TYPE_PMEM:		/* Fall-through: */
	case E820_TYPE_RESERVED:	/* Fall-through: */
	case E820_TYPE_SOFT_RESERVED:	/* Fall-through: */
	default:
	    return IORESOURCE_MEM;
	}
}

static unsigned long __init e820_type_to_iores_desc(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_ACPI:		return IORES_DESC_ACPI_TABLES;
	case E820_TYPE_NVS:		return IORES_DESC_ACPI_NV_STORAGE;
	case E820_TYPE_PMEM:		return IORES_DESC_PERSISTENT_MEMORY;
	case E820_TYPE_PRAM:		return IORES_DESC_PERSISTENT_MEMORY_LEGACY;
	case E820_TYPE_RESERVED:	return IORES_DESC_RESERVED;
	case E820_TYPE_SOFT_RESERVED:	return IORES_DESC_SOFT_RESERVED;
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	default:
	    return IORES_DESC_NONE;
	}
}

static bool __init do_mark_busy(enum e820_type type, struct resource *res)
{
	/* this is the legacy bios/dos rom-shadow + mmio region */
	if (res->start < (1ULL<<20))
		return true;

	/*
	 * Treat persistent memory and other special memory ranges like
	 * device memory, i.e. reserve it for exclusive use of a driver
	 */
	switch (type) {
	case E820_TYPE_RESERVED:
	case E820_TYPE_SOFT_RESERVED:
	case E820_TYPE_PRAM:
	case E820_TYPE_PMEM:
		return false;
	case E820_TYPE_RESERVED_KERN:
	case E820_TYPE_RAM:
	case E820_TYPE_ACPI:
	case E820_TYPE_NVS:
	case E820_TYPE_UNUSABLE:
	default:
		return true;
	}
}

/*
 * Mark E820 reserved areas as busy for the resource manager:
 */

static struct resource __initdata *e820_res;

/**
 *  将 memblock 内存添加至 iomem_resource
 */
void __init e820__reserve_resources(void)
{
	int i;
	struct resource *res;
	u64 end;

	res = memblock_alloc(sizeof(*res) * e820_table->nr_entries, SMP_CACHE_BYTES);
	if (!res)
		panic("%s: Failed to allocate %zu bytes\n", __func__,
		            sizeof(*res) * e820_table->nr_entries);
	e820_res = res;

    /**
     *  遍历 e820_table
     *
     *  Physic Memory
     *
     *  |<--16MB-->|<----------64MB--------->|     |<----reserved--->|<----RAM---->|<-----ACPI----->|
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  |          |                         |     |                 |             |                |
     *  |          |                         | ... |                 |             |                |
     *  |          |                         |     |                 |             |                |
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  ^          ^                               ^                 ^             ^
     *  |          |                               |                 |             |
     *  | +--------+                               |                 |             |
     *  | |     +----------------------------------+                 |             |
     *  | |     | +--------------------------------------------------+             |
     *  | |     | | +--------------------------------------------------------------+
     *  | |     | | |
     *  | |     | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     * | | |   | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | |   | | | | | | | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     *      e820_table
     */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = e820_table->entries + i;

		end = entry->addr + entry->size - 1;
		if (end != (resource_size_t)end) {
			res++;
			continue;
		}

        /**
         *  将所有的      memblock 添加到 resource
         */
		res->start = entry->addr;
		res->end   = end;
		res->name  = e820_type_to_string(entry);
		res->flags = e820_type_to_iomem_type(entry);
		res->desc  = e820_type_to_iores_desc(entry);

		/*
		 * Don't register the region that could be conflicted with
		 * PCI device BAR resources and insert them later in
		 * pcibios_resource_survey():
		 */
		if (do_mark_busy(entry->type, res)) {
			res->flags |= IORESOURCE_BUSY;

            /**
             *  添加至 系统 iomem 资源
             */
			insert_resource(&iomem_resource, res);
		}
		res++;
	}

    /**
     *  固件
     */
	/* Expose the bootloader-provided memory layout to the sysfs. */
	for (i = 0; i < e820_table_firmware->nr_entries; i++) {
		struct e820_entry *entry = e820_table_firmware->entries + i;

		firmware_map_add_early(entry->addr, entry->addr + entry->size, e820_type_to_string(entry));
	}
}

/*
 * How much should we pad the end of RAM, depending on where it is?
 */
static unsigned long __init ram_alignment(resource_size_t pos)
{
	unsigned long mb = pos >> 20;

	/* To 64kB in the first megabyte */
	if (!mb)
		return 64*1024;

	/* To 1MB in the first 16MB */
	if (mb < 16)
		return 1024*1024;

	/* To 64MB for anything above that */
	return 64*1024*1024;
}

#define MAX_RESOURCE_SIZE ((resource_size_t)-1)

void __init e820__reserve_resources_late(void)
{
	int i;
	struct resource *res;

    /**
     *
     */
	res = e820_res;
	for (i = 0; i < e820_table->nr_entries; i++) {
		if (!res->parent && res->end)
			insert_resource_expand_to_fit(&iomem_resource, res);
		res++;
	}

	/*
	 * Try to bump up RAM regions to reasonable boundaries, to
	 * avoid stolen RAM:
	 *
     *  遍历 e820_table
     *
     *  Physic Memory
     *
     *  |<--16MB-->|<----------64MB--------->|     |<----reserved--->|<----RAM---->|<-----ACPI----->|
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  |          |                         |     |                 |             |                |
     *  |          |                         | ... |                 |             |                |
     *  |          |                         |     |                 |             |                |
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  ^          ^                               ^                 ^             ^
     *  |          |                               |                 |             |
     *  | +--------+                               |                 |             |
     *  | |     +----------------------------------+                 |             |
     *  | |     | +--------------------------------------------------+             |
     *  | |     | | +--------------------------------------------------------------+
     *  | |     | | |
     *  | |     | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     * | | |   | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | |   | | | | | | | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     *      e820_table
     */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 start, end;

		if (entry->type != E820_TYPE_RAM)
			continue;

		start = entry->addr + entry->size;
		end = round_up(start, ram_alignment(start)) - 1;
		if (end > MAX_RESOURCE_SIZE)
			end = MAX_RESOURCE_SIZE;
		if (start >= end)
			continue;

		printk(KERN_DEBUG "e820: reserve RAM buffer [mem %#010llx-%#010llx]\n", start, end);

        /**
         *
         */
		reserve_region_with_split(&iomem_resource, start, end, "RAM buffer");
	}
}

/*
 * Pass the firmware (bootloader) E820 map to the kernel and process it:
 */
char *__init e820__memory_setup_default(void)
{
	char *who = "BIOS-e820";

    //$ dmesg | grep e820
    //[    0.000000] e820: BIOS-provided physical RAM map:
    //[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
    //[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bff7ffff] usable
    //[    0.000000] BIOS-e820: [mem 0x00000000bff80000-0x00000000bfffffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
    //[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000023fffffff] usable
    //[    0.000000] e820: update [mem 0x00000000-0x00000fff] usable ==> reserved
    //[    0.000000] e820: remove [mem 0x000a0000-0x000fffff] usable
    //[    0.000000] e820: last_pfn = 0x240000 max_arch_pfn = 0x400000000
    //[    0.000000] e820: last_pfn = 0xbff80 max_arch_pfn = 0x400000000
    //[    0.000000] e820: [mem 0xc0000000-0xfeffbfff] available for PCI devices
    //[    1.146134] e820: reserve RAM buffer [mem 0x0009fc00-0x0009ffff]
    //[    1.146136] e820: reserve RAM buffer [mem 0xbff80000-0xbfffffff]

	/*
	 * Try to copy the BIOS-supplied E820-map.
	 *
	 * Otherwise fake a memory map; one section from 0k->640k,
	 * the next section from 1mb->appropriate_mem_k
	 */
	if (append_e820_table(boot_params.e820_table, boot_params.e820_entries) < 0) {

		u64 mem_size;

		/* Compare results from other methods and take the one that gives more RAM: */
		if (boot_params.alt_mem_k < boot_params.screen_info.ext_mem_k) {
			mem_size = boot_params.screen_info.ext_mem_k;
			who = "BIOS-88";
		} else {
			mem_size = boot_params.alt_mem_k;
			who = "BIOS-e801";
		}

		e820_table->nr_entries = 0;
		e820__range_add(0, LOWMEMSIZE(), E820_TYPE_RAM);
		e820__range_add(HIGH_MEMORY, mem_size << 10, E820_TYPE_RAM);
	}

	/* We just appended a lot of ranges, sanitize the table: */
	e820__update_table(e820_table);

	return who;
}

/**
* 代码的作用
* 该函数 `e820__memory_setup(void)` 用于设置并打印系统内存布局，具体通过 `e820` 机制从 BIOS 获取物理内存的布局信息，并将其记录下来。
* e820 是 BIOS 提供的一个中断服务（INT 0x15，AX=0xE820），用于返回系统内存的分段信息。
* 每段内存有不同的类型和属性，例如“可用”、“保留”等。
*
* 主要步骤：
* 1. **ABI 校验**：
   - 使用 `BUILD_BUG_ON` 检查 `struct boot_e820_entry` 的大小是否符合预期（20 字节），以确保 ABI 兼容性。
* 2. **调用内存初始化函数**：
   - 调用 `x86_init.resources.memory_setup()` 初始化内存设置，这个函数会调用架构特定的内存初始化逻辑。
* 3. **保存内存布局**：
   - 将当前内存布局拷贝到两个全局变量 `e820_table_kexec` 和 `e820_table_firmware` 中，分别用于保存内存布局的快照（用于 Kexec 机制）和原始 BIOS 提供的内存布局。
* 4. **打印内存布局**：
   - 使用 `pr_info` 打印 BIOS 提供的物理内存布局信息到内核日志，并通过 `e820__print_table(who)` 输出详细的内存区域。
*
* 最终效果是通过 BIOS 的 e820 接口获取并打印系统的物理内存布局，为后续的内存管理提供基础信息。
*/
/*
 * Calls e820__memory_setup_default() in essence to pick up the firmware/bootloader
 * E820 map - with an optional platform quirk available for virtual platforms
 * to override this method of boot environment processing:
 */
void __init e820__memory_setup(void)
{
    //e820是和BIOS的一个中断相关的，具体说是int 0x15。
    //之所以叫e820是因为在用这个中断时ax必须是0xe820。
    //这个中断的作用是得到系统的内存布局。
    //因为系统内存会有很多段，每段的类型属性也不一样，所以这个查询是“迭代式”的，每次求得一个段。

	char *who;

	/* This is a firmware interface ABI - make sure we don't break it: */
	BUILD_BUG_ON(sizeof(struct boot_e820_entry) != 20);

    /**
     *  arch/x86/kernel/x86_init.c: .memory_setup = e820__memory_setup_default()
     */
	// 这个应该就是paging_init
	who = x86_init.resources.memory_setup();    /* 内存初始化 */

    /**
     *  将 内存布局拷贝到 零两个全局变量中
     */
	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	pr_info("BIOS-provided physical RAM map:\n");

    //$ dmesg | grep e820
    //[    0.000000] e820: BIOS-provided physical RAM map:
    //[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
    //...
	e820__print_table(who);
}

/**
 * @brief 初始化 memblock
 *
 */
/**
* 代码的作用:
* 该函数 `e820__memblock_setup` 在系统启动的早期阶段，用于根据 BIOS 提供的 e820 内存映射表（BIOS-e820）设置和初始化 `memblock` 结构。
* `memblock` 是 Linux 内核用于管理物理内存的一个早期数据结构，允许预留和管理内存区域。
*
* 详细步骤如下：
* 1. `memblock_allow_resize()`：允许 `memblock` 的大小进行动态调整，确保它可以容纳足够的内存区域条目。EFI 可能会提供比默认最大数量（128 个）更多的 e820 条目，因此需要此调整。
* 2. 遍历 e820 表的所有内存条目（`e820_table->nr_entries`），并检查每个内存区域的结束地址是否超出 64 位物理地址空间（`resource_size_t`），如果是则跳过该条目。
* 3. 对每个有效条目进行进一步处理：
   - 如果条目类型为 `E820_TYPE_SOFT_RESERVED`，表示这是保留区域，将其加入 `memblock.reserved`，以确保内核不会使用这些区域。
   - 如果条目类型是 `E820_TYPE_RAM` 或 `E820_TYPE_RESERVED_KERN`，则将其添加到 `memblock.memory` 中，这些区域可供系统使用。
* 4. 调用 `memblock_trim_memory(PAGE_SIZE)`，对内存块进行调整，丢弃小于一个页面大小的部分，确保内存块以页面为单位管理。
* 5. 最后，调用 `memblock_dump_all()`，将所有 memblock 的状态打印出来，便于调试和确认内存块的分配情况。
*
* 该函数的主要作用是基于 BIOS 提供的 e820 内存表，设置内存块的预留和可用区域，确保系统启动时正确管理物理内存。
*/
void __init e820__memblock_setup(void)
{
//[rongtao@localhost src]$ dmesg | grep e820
//[    0.000000] e820: BIOS-provided physical RAM map:
//[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
//[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
//[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
//[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bff7ffff] usable
//[    0.000000] BIOS-e820: [mem 0x00000000bff80000-0x00000000bfffffff] reserved
//[    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved
//[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
//[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000023fffffff] usable
//[    0.000000] e820: update [mem 0x00000000-0x00000fff] usable ==> reserved
//[    0.000000] e820: remove [mem 0x000a0000-0x000fffff] usable
//[    0.000000] e820: last_pfn = 0x240000 max_arch_pfn = 0x400000000
//[    0.000000] e820: last_pfn = 0xbff80 max_arch_pfn = 0x400000000
//[    0.000000] e820: [mem 0xc0000000-0xfeffbfff] available for PCI devices
//[    1.258057] e820: reserve RAM buffer [mem 0x0009fc00-0x0009ffff]
//[    1.258059] e820: reserve RAM buffer [mem 0xbff80000-0xbfffffff]
	int i;
	u64 end;

	/*
	 * The bootstrap memblock region count maximum is 128 entries
	 * (INIT_MEMBLOCK_REGIONS), but EFI might pass us more E820 entries
	 * than that - so allow memblock resizing.
	 *
	 * This is safe, because this call happens pretty late during x86 setup,
	 * so we know about reserved memory regions already. (This is important
	 * so that memblock resizing does no stomp over reserved areas.)
	 */
	memblock_allow_resize();

    /**
     *
     *  Physic Memory
     *
     *  |<--16MB-->|<----------64MB--------->|     |<----reserved--->|<----RAM---->|<-----ACPI----->|
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  |          |                         |     |                 |             |                |
     *  |          |                         | ... |                 |             |                |
     *  |          |                         |     |                 |             |                |
     *  +----------+-------------------------+-----+-----------------+-------------+----------------+
     *  ^          ^                               ^                 ^             ^
     *  |          |                               |                 |             |
     *  | +--------+                               |                 |             |
     *  | |     +----------------------------------+                 |             |
     *  | |     | +--------------------------------------------------+             |
     *  | |     | | +--------------------------------------------------------------+
     *  | |     | | |
     *  | |     | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     * | | |   | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | | . | | | | | | | | |
     * | | |   | | | | | | | | |
     * +-+-+---+-+-+-+-+-+-+-+-+
     *      e820_table 遍历
     */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		end = entry->addr + entry->size;

        /**
         *  检测 地址类型
         */
		if (end != (resource_size_t)end)
			continue;

        /**
         *  预留，这将添加至 memblock.reserved 中
         */
		if (entry->type == E820_TYPE_SOFT_RESERVED)
			memblock_reserve(entry->addr, entry->size);

		if (entry->type != E820_TYPE_RAM && entry->type != E820_TYPE_RESERVED_KERN)
			continue;

        /**
         *  将 RAM 和 给 kernel 的 ram 添加至 memblock.memory 中
         */
		memblock_add(entry->addr, entry->size);
	}

	/* Throw away partial pages: */
	memblock_trim_memory(PAGE_SIZE);

    /**
     *  显示 一波
     */
	memblock_dump_all();
}
