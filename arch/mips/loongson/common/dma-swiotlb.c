#include <linux/types.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>
#include <linux/scatterlist.h>

#include <asm/bootinfo.h>

#include <dma-coherence.h>

static dma_addr_t loongson_dma_map_page(struct device *dev, struct page *page,
	unsigned long offset, size_t size, enum dma_data_direction direction, 
	struct dma_attrs *attrs)
{
	dma_addr_t daddr = swiotlb_map_page(dev, page, offset, size,
						direction, attrs);

#ifdef LOONGSON_BIGMEM_DEBUG
	if((daddr_ >= 0x90000000) || (daddr < 0x80000000)){
		printk("+++%s %s: daddr(0x%lx)\n", __FILE__, __func__, daddr);
		dump_stack();
	}
#endif

	mb();

	return daddr;
}

static int loongson_dma_map_sg(struct device *dev, struct scatterlist *sg,
	int nents, enum dma_data_direction direction, struct dma_attrs *attrs)
{
	int r = swiotlb_map_sg_attrs(dev, sg, nents, direction, NULL);
	mb();
	return r;
}

static void loongson_dma_sync_single_for_device(struct device *dev,
	dma_addr_t dma_handle, size_t size, enum dma_data_direction direction)
{
	swiotlb_sync_single_for_device(dev, dma_handle, size, direction);
	mb();
}

static void loongson_dma_sync_sg_for_device(struct device *dev,
	struct scatterlist *sg, int nelems, enum dma_data_direction direction)
{
	swiotlb_sync_sg_for_device(dev, sg, nelems, direction);
	mb();
}

static void *loongson_dma_alloc_coherent(struct device *dev, size_t size,
	dma_addr_t *dma_handle, gfp_t gfp)
{
	void *ret;

	if (dma_alloc_from_coherent(dev, size, dma_handle, &ret))
		return ret;

	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM);

#ifdef CONFIG_ZONE_DMA
	if (dev == NULL)
		gfp |= __GFP_DMA;
	else if (dev->coherent_dma_mask <= DMA_BIT_MASK(24))
		gfp |= __GFP_DMA;
	else
#endif
#ifdef CONFIG_ZONE_DMA32
	if (dev == NULL)
		gfp |= __GFP_DMA32;
	else if (dev->coherent_dma_mask <= DMA_BIT_MASK(32))
		gfp |= __GFP_DMA32;
	else
#endif
		;

	/* Don't invoke OOM killer */
	gfp |= __GFP_NORETRY;

	ret = swiotlb_alloc_coherent(dev, size, dma_handle, gfp);

#ifdef LOONGSON_BIGMEM_DEBUG
	if((*dma_handle >= 0x90000000) || (*dma_handle < 0x80000000)){
		printk("+++%s %s: *dma_handle(0x%lx)\n", __FILE__, __func__, *dma_handle);
		dump_stack();
	}
#endif

	mb();

	return ret;
}

static void loongson_dma_free_coherent(struct device *dev, size_t size,
	void *vaddr, dma_addr_t dma_handle)
{
	int order = get_order(size);

	if (dma_release_from_coherent(dev, order, vaddr))
		return;

	swiotlb_free_coherent(dev, size, vaddr, dma_handle);
}

static struct mips_dma_map_ops loongson_linear_dma_map_ops = {
	.dma_map_ops = {
		.alloc_coherent		= loongson_dma_alloc_coherent,
		.free_coherent		= loongson_dma_free_coherent,
		.map_page		= loongson_dma_map_page,
		.unmap_page		= swiotlb_unmap_page,
		.map_sg			= loongson_dma_map_sg,
		.unmap_sg		= swiotlb_unmap_sg_attrs,
		.sync_single_for_cpu	= swiotlb_sync_single_for_cpu,
		.sync_single_for_device	= loongson_dma_sync_single_for_device,
		.sync_sg_for_cpu	= swiotlb_sync_sg_for_cpu,
		.sync_sg_for_device	= loongson_dma_sync_sg_for_device,
		.mapping_error		= swiotlb_dma_mapping_error,
		.dma_supported		= swiotlb_dma_supported
	},
	.phys_to_dma	= mips_unity_phys_to_dma,
	.dma_to_phys	= mips_unity_dma_to_phys
};

void __init plat_swiotlb_setup(void)
{
	int i;
	phys_t max_addr;
	phys_t addr_size;
	size_t swiotlbsize;

	max_addr = 0;
	addr_size = 0;

	if(!dma64_supported) {
		loongson_linear_dma_map_ops.phys_to_dma = mips_unity_phys_to_dma32;
		loongson_linear_dma_map_ops.dma_to_phys = mips_unity_dma_to_phys32;
		pr_info("swiotlb:restricted 32bit dma!\n");
	}
	for (i = 0 ; i < boot_mem_map.nr_map; i++) {
		struct boot_mem_map_entry *e = &boot_mem_map.map[i];
		if (e->type != BOOT_MEM_RAM)
			continue;

		/* These addresses map low for PCI. */
		if (e->addr > 0x410000000ull)
			continue;

		addr_size += e->size;

		if (max_addr < e->addr + e->size)
			max_addr = e->addr + e->size;
	}
	swiotlbsize = 64 * (1<<20); 

	printk("SWIOTLB: swiotlbsize = 0x%lx\n", swiotlbsize);
	swiotlb_init_with_default_size(swiotlbsize, 1);


	mips_dma_map_ops = &loongson_linear_dma_map_ops;
}

