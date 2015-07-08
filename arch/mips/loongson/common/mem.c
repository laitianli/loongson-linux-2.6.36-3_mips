/*
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/mm.h>

#include <asm/bootinfo.h>
#include <boot_param.h>
#include <loongson.h>
#include <mem.h>
#include <pci.h>

extern unsigned long smbios_addr;

void __init prom_init_memory(void)
{
#ifndef CONFIG_UEFI_FIRMWARE_INTERFACE
	add_memory_region(0x0, (memsize << 20), BOOT_MEM_RAM);

	add_memory_region(memsize << 20, LOONGSON_PCI_MEM_START - (memsize <<
				20), BOOT_MEM_RESERVED);

#ifdef CONFIG_CPU_SUPPORTS_ADDRWINCFG
	{
		int bit;

		bit = fls(memsize + highmemsize);
		if (bit != ffs(memsize + highmemsize))
			bit += 20;
		else
			bit = bit + 20 - 1;

		/* set cpu window3 to map CPU to DDR: 2G -> 2G */
		LOONGSON_ADDRWIN_CPUTODDR(ADDRWIN_WIN3, 0x80000000ul,
					0x80000000ul, (1 << bit));
		mmiowb();
	}
#endif /* !CONFIG_CPU_SUPPORTS_ADDRWINCFG */

#ifdef CONFIG_64BIT
#ifdef CONFIG_CPU_LOONGSON2H
	add_memory_region(0x110000000, highmemsize << 20, BOOT_MEM_RAM);
#else
	if (highmemsize > 0)
		add_memory_region(LOONGSON_HIGHMEM_START,
				highmemsize << 20, BOOT_MEM_RAM);

	add_memory_region(LOONGSON_PCI_MEM_END + 1, LOONGSON_HIGHMEM_START -
			LOONGSON_PCI_MEM_END - 1, BOOT_MEM_RESERVED);
#endif /* CONFIG_CPU_LOONGSON2H */
#endif /* !CONFIG_64BIT */

#else	/* CONFIG_UEFI_FIRMWARE_INTERFACE */
	u64 node_id, mem_size;
	u32 i, mem_type, total_memsize;
	total_memsize = 0;

	/* parse memory information */
	for (i = 0; i < emap->nr_map; i++){
		node_id = emap->map[i].node_id;
		mem_type = emap->map[i].mem_type;
		mem_size = emap->map[i].mem_size;

		if (node_id == 0) {
			switch (mem_type) {
			case SYSTEM_RAM_LOW:
			case SYSTEM_RAM_HIGH:
				total_memsize += mem_size;
				add_memory_region(emap->map[i].mem_start,
					mem_size << 20, BOOT_MEM_RAM);
				break;
			case SMBIOS_TABLE:
				smbios_addr = emap->map[i].mem_start & 0x000000000fffffff;	
				printk("smbios_addr : 0x%lx\n", smbios_addr);
				break;
			case MEM_RESERVED:
				add_memory_region(emap->map[i].mem_start,
					mem_size << 20, BOOT_MEM_RESERVED);
				break;
			}
		}
	}

	/*
	 * Just for compatibility previous loongson3A kernel.
	 * reserve the memory 0xff800000~0xffffffff for RS780E
	 * integrated GPU when system ram more than 2G.
	 */
	add_memory_region(0x0, 0x1000000, BOOT_MEM_RESERVED);
	if((board_type == RS780E) && (total_memsize >= 2032))
		add_memory_region(0xff800000, 0x800000, BOOT_MEM_RESERVED);
#endif
}

/* override of arch/mips/mm/cache.c: __uncached_access */
int __uncached_access(struct file *file, unsigned long addr)
{
	if (file->f_flags & O_DSYNC)
		return 1;

	return addr >= __pa(high_memory) ||
		((addr >= LOONGSON_MMIO_MEM_START) &&
		 (addr < LOONGSON_MMIO_MEM_END));
}

#ifdef CONFIG_CPU_SUPPORTS_UNCACHED_ACCELERATED

#include <linux/pci.h>
#include <linux/sched.h>
#include <asm/current.h>

static unsigned long uca_start, uca_end;

pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
				unsigned long size, pgprot_t vma_prot)
{
	unsigned long offset = pfn << PAGE_SHIFT;
	unsigned long end = offset + size;

	if (__uncached_access(file, offset)) {
		if (uca_start && (offset >= uca_start) &&
						(end <= uca_end))
			return __pgprot((pgprot_val(vma_prot) &
					 ~_CACHE_MASK) |
					_CACHE_UNCACHED_ACCELERATED);
		else
			return pgprot_noncached(vma_prot);
	}
	return vma_prot;
}

static int __init find_vga_mem_init(void)
{
	struct pci_dev *dev = 0;
	struct resource *r;
	int idx;

	if (uca_start)
		return 0;

	for_each_pci_dev(dev) {
		if ((dev->class >> 16) == PCI_BASE_CLASS_DISPLAY) {
			for (idx = 0; idx < PCI_NUM_RESOURCES; idx++) {
				r = &dev->resource[idx];
				if (!r->start && r->end)
					continue;
				if (r->flags & IORESOURCE_IO)
					continue;
				if (r->flags & IORESOURCE_MEM) {
					uca_start = r->start;
					uca_end = r->end;
					return 0;
				}
			}
		}
	}
	return 0;
}

late_initcall(find_vga_mem_init);
#endif /* !CONFIG_CPU_SUPPORTS_UNCACHED_ACCELERATED */
