/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2006, 07  Ralf Baechle <ralf@linux-mips.org>
 * Copyright (C) 2007 Lemote, Inc. & Institute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
 *
 */
#ifndef __ASM_MACH_LOONGSON_DMA_COHERENCE_H
#define __ASM_MACH_LOONGSON_DMA_COHERENCE_H

struct device;

static inline dma_addr_t plat_map_dma_mem(struct device *dev, void *addr,
					  size_t size)
{
#ifdef CONFIG_CPU_LOONGSON3
	unsigned long uaddr;
	dma_addr_t tmp;
	//pr_info("%s %s %lx \n", __func__, dev_name(dev), addr);

	uaddr = (virt_to_phys(addr) < 0x10000000) ?
		  (virt_to_phys(addr) | 0x0000000080000000) : virt_to_phys(addr);
#ifdef CONFIG_PHYS48_TO_HT40
	 /* we extract 2bit node id(bit 44~47, only bit 44~45 used now) from
	  * loongson3's 48bit address space and embed it into 40bit */
	tmp = (uaddr >> 44) & 0x3;
	uaddr = ((tmp << 44 ) ^ uaddr) | (tmp << 37);
#endif
	return uaddr;

#elif defined(CONFIG_CPU_LOONGSON2H)
	return virt_to_phys(addr) | 0x40000000;
#else
	return virt_to_phys(addr) | 0x80000000;
#endif 
}

static inline unsigned long plat_dma_addr_to_phys(struct device *dev,
	dma_addr_t dma_addr)
{
#ifdef CONFIG_64BIT

#ifdef CONFIG_CPU_LOONGSON2H
	return dma_addr & 0x3fffffff;
#endif /* CONFIG_CPU_LOONGSON2H */

#ifdef CONFIG_CPU_LOONGSON3
	dma_addr =  (dma_addr < 0x90000000 && dma_addr >= 0x80000000) ?
			(dma_addr & 0x0fffffff) : dma_addr;
#ifdef CONFIG_PHYS48_TO_HT40
	dma_addr_t tmp;
	tmp = (dma_addr >> 37) & 0x3;
	dma_addr = ((tmp << 37 ) ^ dma_addr) | (tmp << 44);
#endif
	return dma_addr;
#endif

#ifdef CONFIG_CPU_LOONGSON2F
	return (dma_addr > 0x8fffffff) ? dma_addr : (dma_addr & 0x0fffffff);
#endif

#else

#ifdef CONFIG_CPU_LOONGSON2H
	return dma_addr & 0x3fffffff;
#else
	return dma_addr & 0x7fffffff;
#endif /* CONFIG_CPU_LOONGSON2H */
#endif /* CONFIG_64BIT */
}

static inline void plat_unmap_dma_mem(struct device *dev, dma_addr_t dma_addr,
	size_t size, enum dma_data_direction direction)
{
}

static inline int plat_dma_supported(struct device *dev, u64 mask)
{
	/*
	 * we fall back to GFP_DMA when the mask isn't all 1s,
	 * so we can't guarantee allocations that must be
	 * within a tighter range than GFP_DMA..
	 */
	if (mask < DMA_BIT_MASK(24))
		return 0;

	return 1;
}

static inline void plat_extra_sync_for_device(struct device *dev)
{
	return;
}

static inline int plat_dma_mapping_error(struct device *dev,
					 dma_addr_t dma_addr)
{
	return 0;
}

static inline int plat_device_is_coherent(struct device *dev)
{
#ifdef CONFIG_DMA_NONCOHERENT
	return 0;
#else
	return 1;
#endif
}

#endif /* __ASM_MACH_LOONGSON_DMA_COHERENCE_H */
