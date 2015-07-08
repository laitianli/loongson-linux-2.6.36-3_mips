/*
 * Copyright (C) 2010 Loongson Inc. & Insititute of Computing Technology
 * Author:  Gao Xiang, gaoxiang@ict.ac.cn
 *          Meng Xiaofu, Zhang Shuangshuang
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include <linux/pfn.h>
#include <linux/highmem.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <linux/bootmem.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <asm/bootinfo.h>
#include <asm/mc146818-time.h>
#include <asm/time.h>
#include <asm/wbflush.h>
#include <boot_param.h>

extern void prom_printf(char *fmt, ...);
extern unsigned int nodes_loongson;
extern unsigned int nr_cpu_loongson;
extern struct efi_memory_map_loongson *emap;
#define MAX_NODES nodes_loongson

static unsigned int cpu_num;
static struct node_data prealloc__node_data[MAX_NUMNODES];
unsigned char __node_distances[MAX_NUMNODES][MAX_NUMNODES];
struct node_data *__node_data[MAX_NUMNODES];
EXPORT_SYMBOL(__node_data);
extern unsigned long smbios_addr;

static void enable_lpa(void)
{
	unsigned long value;

	value = __read_32bit_c0_register($16, 3);
	value |= 0x00000080;
	__write_32bit_c0_register($16, 3, value);
	value = __read_32bit_c0_register($16, 3);
	prom_printf("CP0_Config3: CP0 16.3 (0x%lx)\n", value);

	value = __read_32bit_c0_register($5, 1);
	value |= 0x20000000;
	__write_32bit_c0_register($5, 1, value);
	value = __read_32bit_c0_register($5, 1);
	prom_printf("CP0_PageGrain: CP0 5.1 (0x%lx)\n", value);
}

static __init init_topology_matrix(void)
{
	signed short nasid, nasid2;
	signed short row, col;

	for (row = 0; row < MAX_NODES; row++)
		for (col = 0; col < MAX_NODES; col++) {
			if (row == col)
				__node_distances[row][col] = 1;
			else
				__node_distances[row][col] = 200;
		}
}

static void cpu_node_probe(void)
{
	int i;

	nodes_clear(node_online_map);
	for (i = 0; i < MAX_NODES; i++) {
		node_set_online(num_online_nodes());
	}

	printk("NUMA: Discovered %d cpus on %d nodes\n", cpu_num, num_online_nodes());
	prom_printf("NUMA: Discovered %d cpus on %d nodes\n", cpu_num, num_online_nodes());
}

static int node_has_mem(unsigned int nid)
{
	u64 node_id, mem_size;
	u32 i, result, mem_type;

	/* parse memory information */
	for (i = 0; i < emap->nr_map; i++) {
		node_id = emap->map[i].node_id;
		mem_type = emap->map[i].mem_type;
		mem_size = emap->map[i].mem_size;

		if (node_id == nid) {
			switch (mem_type) {
			case SYSTEM_RAM_LOW:
			case SYSTEM_RAM_HIGH:
				result = mem_size > 0 ? 1 : 0;
				if (result)
					return result;
				break;
			case MEM_RESERVED:
				break;
			}
		}
	}

	return result;
}

static unsigned long nid_to_addroffset(unsigned int nid)
{
	unsigned long result;
	switch(nid){
	case 0:
		result = NODE0_ADDRSPACE_OFFSET;
		break;
	case 1:
		result = NODE1_ADDRSPACE_OFFSET;
		break;
	case 2:
		result = NODE2_ADDRSPACE_OFFSET;
		break;
	case 3:
		result = NODE3_ADDRSPACE_OFFSET;
		break;
	}
	return result;
}

static void __init szmem(unsigned int node)
{
	u64 node_id, node_psize, start_pfn, end_pfn, mem_size;
	u32 i, mem_type;

	/* parse memory information and active */
	for (i = 0; i < emap->nr_map; i++) {
		node_id = emap->map[i].node_id;
		mem_type = emap->map[i].mem_type;
		mem_size = emap->map[i].mem_size;

		if (node_id == node) {
			switch (mem_type) {
			case SYSTEM_RAM_LOW:
				start_pfn = (node_id << 44) >> PAGE_SHIFT;
				node_psize = ((mem_size + 16) << 20) >> PAGE_SHIFT;
				end_pfn  = start_pfn + node_psize;
				num_physpages += node_psize;
				prom_printf("Debug: node_id:%d, mem_type:%d, mem_start:0x%lx, mem_size:0x%lx MB\n",
					node_id, mem_type, emap->map[i].mem_start, mem_size);
				prom_printf("       start_pfn:0x%lx, end_pfn:0x%lx, num_physpages:0x%lx\n",
					start_pfn, end_pfn, num_physpages);
				add_active_range(node, start_pfn, end_pfn);
				break;
			case SYSTEM_RAM_HIGH:
				start_pfn = ((node_id << 44) + emap->map[i].mem_start) >> PAGE_SHIFT;
				node_psize = (mem_size << 20) >> PAGE_SHIFT;
				end_pfn  = start_pfn + node_psize;
				num_physpages += node_psize;
				prom_printf("Debug: node_id:%d, mem_type:%d, mem_start:0x%lx, mem_size:0x%lx MB\n",
					node_id, mem_type, emap->map[i].mem_start, mem_size);
				prom_printf("       start_pfn:0x%lx, end_pfn:0x%lx, num_physpages:0x%lx\n",
					start_pfn, end_pfn, num_physpages);
				add_active_range(node, start_pfn, end_pfn);
				break;
			case SMBIOS_TABLE:
				smbios_addr = emap->map[i].mem_start & 0x000000000fffffff;	
				prom_printf("smbios_addr : 0x%lx\n", smbios_addr);
				break;
			case MEM_RESERVED:
				break;
			}
		}
	}
}

static void __init node_mem_init(unsigned int node)
{
	unsigned long bootmap_size;
	unsigned long node_addrspace_offset;
	unsigned long start_pfn, end_pfn, freepfn;
	u32 i, mem_type;
#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
	u64 available_memsize, reserved_memsize;
#endif
	u64 node_id, mem_size, total_memsize;
	total_memsize = 0;

	node_addrspace_offset = nid_to_addroffset(node);
	prom_printf("node%d's addrspace_offset is 0x%lx\n", node, node_addrspace_offset);

	get_pfn_range_for_nid(node, &start_pfn, &end_pfn);
	freepfn = start_pfn;
	if(node == 0)
		freepfn = PFN_UP(__pa_symbol(&_end)); //kernel binary end address
	prom_printf("node%d's start_pfn is 0x%lx, end_pfn is 0x%lx, freepfn is 0x%lx\n",node,start_pfn,end_pfn,freepfn);

	__node_data[node] = prealloc__node_data + node;

	NODE_DATA(node)->bdata = &bootmem_node_data[node];
	NODE_DATA(node)->node_start_pfn = start_pfn;
	NODE_DATA(node)->node_spanned_pages = end_pfn - start_pfn;

	bootmap_size = init_bootmem_node(NODE_DATA(node), freepfn,
					start_pfn, end_pfn);
	free_bootmem_with_active_regions(node, end_pfn);

	/*this is reserved for the kernel and bdata->node_bootmem_map*/
	reserve_bootmem_node(NODE_DATA(node), start_pfn << PAGE_SHIFT, \
		((freepfn - start_pfn) << PAGE_SHIFT) + bootmap_size, \
		BOOTMEM_DEFAULT);

	/* parse memory information and active */
	for (i = 0; i < emap->nr_map; i++) {
		node_id = emap->map[i].node_id;
		mem_type = emap->map[i].mem_type;
		mem_size = emap->map[i].mem_size;

		if (node_id == node) {
			switch (mem_type) {
			case SYSTEM_RAM_LOW:
			case SYSTEM_RAM_HIGH:
				total_memsize += mem_size;
				break;
			case MEM_RESERVED:
				prom_printf("Debug: node_id:%d, mem_type:%d, mem_start:0x%lx, mem_size:0x%lx MB\n",
					node_id, mem_type, emap->map[i].mem_start, mem_size);
				reserve_bootmem_node(NODE_DATA(node), \
					((node_id << 44) | emap->map[i].mem_start), \
					mem_size << 20, BOOTMEM_DEFAULT);
				break;
			}
		}
	}
	total_memsize += 16;
	prom_printf("Mengxf: total_memsize :0x%lx MB\n", total_memsize);

#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
	available_memsize = CONFIG_TOTAL_SYSTEM_MEMSIZE*1024;
	if (total_memsize < available_memsize)
		available_memsize = total_memsize;
	reserved_memsize = (total_memsize - available_memsize + 2048) << 20;
	prom_printf("Mengxf: reserved_memsize :0x%lx Bytes\n", reserved_memsize);
#endif

	/* Just for compatibility previous loongson3A kernel */
	if(node == 0) {
		/* reserve the memory 0x0~0x1000000 for bios runtime service */
		reserve_bootmem_node(NODE_DATA(node), \
				(node_addrspace_offset | 0x0), 16 << 20, BOOTMEM_DEFAULT);

		/* reserve the memory 0xf000000~0x10000000 for RS780E integrated GPU */
                reserve_bootmem_node(NODE_DATA(node), \
                                (node_addrspace_offset | 0xf000000), 16 << 20, BOOTMEM_DEFAULT);

		/* reserve the memory 0xff800000~0xffffffff for RS780E integrated GPU */
		if((board_type == RS780E) && (total_memsize >= 2048))
			reserve_bootmem_node(NODE_DATA(node), \
					(node_addrspace_offset | 0xff800000), 8 << 20, BOOTMEM_DEFAULT);
	}

	/* reserve the memory hole from 256M to (256M+2G) */
	if(node_has_mem(node)) {
		if(board_type == RS780E)
#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
			reserve_bootmem_node(NODE_DATA(node), \
				(node_addrspace_offset | 0x10000000), \
				reserved_memsize, BOOTMEM_DEFAULT);
#else
			reserve_bootmem_node(NODE_DATA(node), \
				(node_addrspace_offset | 0x10000000), \
				0x80000000, BOOTMEM_DEFAULT);
#endif

		if(board_type == LS2H)
			reserve_bootmem_node(NODE_DATA(node), \
				(node_addrspace_offset | 0x10000000), \
				0x100000000, BOOTMEM_DEFAULT);
	}
	sparse_memory_present_with_active_regions(node);
}

static __init void prom_meminit(void)
{
	unsigned int node, cpu;
	unsigned int cpu_num_pernode = nr_cpu_loongson >> (MAX_NODES >> 1);
	unsigned int master_cpuid;
	cpu_num = nr_cpu_loongson;

	master_cpuid = smp_processor_id();
	prom_printf("Caller cpu %d\n", master_cpuid);
	printk(KERN_INFO "Caller cpu %d\n", master_cpuid);

	cpu_node_probe();
	init_topology_matrix();
	num_physpages = 0;

	for (node = 0; node < MAX_NODES; node++) {
		if (node_online(node)) {
			szmem(node);
			node_mem_init(node);
			cpus_clear(__node_data[(node)]->cpumask);///gx GX TODO
		}
	}
	for (cpu = 0; cpu < cpu_num; cpu++) {
		node = cpu / cpu_num_pernode;
		if(node >= num_online_nodes())
			node = 0;
		prom_printf("NUMA: set cpumask cpu %d on node %d\n", cpu, node);
		cpu_set(cpu, __node_data[(node)]->cpumask);///gx GX TODO
	}
}

void __init paging_init(void)
{
	unsigned long zones_size[MAX_NR_ZONES] = {0, };
	unsigned node;

	pagetable_init();

	for_each_online_node(node) {
		unsigned long  start_pfn, end_pfn;

		get_pfn_range_for_nid(node, &start_pfn, &end_pfn);

		if (end_pfn > max_low_pfn)
			max_low_pfn = end_pfn;
	}
#ifdef CONFIG_ZONE_DMA32
	zones_size[ZONE_DMA32] = MAX_DMA32_PFN;
#endif
	zones_size[ZONE_NORMAL] = max_low_pfn;
	free_area_init_nodes(zones_size);
}

extern unsigned long setup_zero_pages(void);

void __init mem_init(void)
{
	unsigned long codesize, datasize, initsize, tmp;
	unsigned node;

	high_memory = (void *) __va(num_physpages << PAGE_SHIFT);
	prom_printf("total ram pages initialed %d\n", totalram_pages);

	for_each_online_node(node) {
		/*
		 * This will free up the bootmem, ie, slot 0 memory.
		 */
		totalram_pages += free_all_bootmem_node(NODE_DATA(node));
		prom_printf("total ram pages are %d\n",totalram_pages);
	}

	totalram_pages -= setup_zero_pages();	/* This comes from node 0 */

	codesize = (unsigned long) &_etext - (unsigned long) &_text;
	datasize = (unsigned long) &_edata - (unsigned long) &_etext;
	initsize = (unsigned long) &__init_end - (unsigned long) &__init_begin;

	tmp = nr_free_pages();
	printk(KERN_INFO "Memory: %luk/%luk available (%ldk kernel code, "
		"%ldk reserved, %ldk data, %ldk init, %ldk highmem)\n",
		tmp << (PAGE_SHIFT-10),
		num_physpages << (PAGE_SHIFT-10),
		codesize >> 10,
		(num_physpages - tmp) << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10,
		(unsigned long) (totalhigh_pages << (PAGE_SHIFT-10)));
}

/* All PCI device belongs to logical node0*/
int pcibus_to_node(struct pci_bus *bus)
{
	return 0;
}
EXPORT_SYMBOL(pcibus_to_node);

void prom_init_numa_memory(void)
{
	enable_lpa();
	prom_meminit();
}
EXPORT_SYMBOL(prom_init_numa_memory);
