#ifndef _ASM_DMA_MAPPING_H
#define _ASM_DMA_MAPPING_H

#include <asm/scatterlist.h>
#include <asm/cache.h>
#include <asm-generic/dma-coherent.h>
#if defined (CONFIG_CPU_LOONGSON3) || defined (CONFIG_CPU_LOONGSON2H)
extern uint32_t dma64_supported;
#endif

struct mips_dma_map_ops {
	struct dma_map_ops dma_map_ops;
	dma_addr_t (*phys_to_dma)(struct device *dev, phys_addr_t paddr);
	phys_addr_t (*dma_to_phys)(struct device *dev, dma_addr_t daddr);
};

extern struct mips_dma_map_ops *mips_dma_map_ops;

static inline struct dma_map_ops *get_dma_ops(struct device *dev)
{
	struct mips_dma_map_ops *ops;

	if (dev && dev->archdata.dma_ops)
		ops = dev->archdata.dma_ops;
	else
		ops = mips_dma_map_ops;

	return &ops->dma_map_ops;
}

static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	struct mips_dma_map_ops *ops = container_of(get_dma_ops(dev),
						    struct mips_dma_map_ops,
						    dma_map_ops);

	return ops->phys_to_dma(dev, paddr);
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	struct mips_dma_map_ops *ops = container_of(get_dma_ops(dev),
						    struct mips_dma_map_ops,
						    dma_map_ops);

	return ops->dma_to_phys(dev, daddr);
}

static inline bool dma_capable(struct device *dev, dma_addr_t addr, size_t size)
{
	if (!dev->dma_mask)
		return 0;
#if defined (CONFIG_CPU_LOONGSON3) || defined (CONFIG_CPU_LOONGSON2H)
	if (!dma64_supported)
		return addr + size <= 0x00000000ffffffff;
	else
#endif

	return addr + size <= *dev->dma_mask;
}

static inline void dma_mark_clean(void *addr, size_t size) {}

#include <asm-generic/dma-mapping-common.h>

static inline int dma_supported(struct device *dev, u64 mask)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	return ops->dma_supported(dev, mask);
}

static inline int dma_mapping_error(struct device *dev, u64 mask)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	return ops->mapping_error(dev, mask);
}

static inline int
dma_set_mask(struct device *dev, u64 mask)
{
	if(!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}

extern void dma_cache_sync(struct device *dev, void *vaddr, size_t size,
	       enum dma_data_direction direction);

static inline void *dma_alloc_coherent(struct device *dev, size_t size,
				       dma_addr_t *dma_handle, gfp_t gfp)
{
	void *ret;
	struct dma_map_ops *ops = get_dma_ops(dev);

	ret = ops->alloc_coherent(dev, size, dma_handle, gfp);

	debug_dma_alloc_coherent(dev, size, *dma_handle, ret);

	return ret;
}

static inline void dma_free_coherent(struct device *dev, size_t size,
				     void *vaddr, dma_addr_t dma_handle)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	ops->free_coherent(dev, size, vaddr, dma_handle);

	debug_dma_free_coherent(dev, size, vaddr, dma_handle);
}


void *dma_alloc_noncoherent(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, gfp_t flag);

void dma_free_noncoherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle);

dma_addr_t mips_unity_phys_to_dma(struct device *dev, phys_addr_t paddr);
phys_addr_t mips_unity_dma_to_phys(struct device *dev, dma_addr_t daddr);

dma_addr_t mips_unity_phys_to_dma32(struct device *dev, phys_addr_t paddr);
phys_addr_t mips_unity_dma_to_phys32(struct device *dev, dma_addr_t daddr);

#endif /* _ASM_DMA_MAPPING_H */
