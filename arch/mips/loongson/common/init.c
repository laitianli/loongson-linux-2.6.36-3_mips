/*
 * Copyright (C) 2009 Lemote Inc.
 * Author: Wu Zhangjin, wuzhangjin@gmail.com
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <loongson.h>
#include <asm/smp-ops.h>
#include <boot_param.h>
#include <linux/bootmem.h>
#include <htregs.h>
#include <ls2h/ls2h.h>

extern void prom_printf(char *fmt, ...);
extern void prom_init_numa_memory(void);
extern struct plat_smp_ops loongson3_smp_ops;
/* Loongson CPU address windows config space base address */
unsigned long __maybe_unused _loongson_addrwincfg_base;

void __init prom_init(void)
{
	/* init base address of io space */
#ifdef CONFIG_CPU_SUPPORTS_ADDRWINCFG
	_loongson_addrwincfg_base = (unsigned long)
		ioremap(LOONGSON_ADDRWINCFG_BASE, LOONGSON_ADDRWINCFG_SIZE);
#endif

	prom_init_cmdline();
	prom_init_env();
#ifdef CONFIG_CPU_LOONGSON2H
	set_io_port_base(CKSEG1ADDR(LS2H_LPC_IO_BASE));
#else
	set_io_port_base((unsigned long)
	ioremap(LOONGSON_PCIIO_BASE, LOONGSON_PCIIO_SIZE));
#endif

#ifdef CONFIG_NUMA
	prom_init_numa_memory();
#else
	prom_init_memory();
#endif

	/*init the uart base address */
	prom_init_uart_base();

#ifdef CONFIG_SMP
	register_smp_ops(&loongson3_smp_ops);
#endif

#ifdef CONFIG_CPU_LOONGSON3
#ifdef CONFIG_DMA_NONCOHERENT
	/* set HT-access uncache */
	HT_uncache_enable_reg0	= 0xc0000000;
	HT_uncache_base_reg0	= 0x0080ff80;
#else
	/* set HT-access cache */
	HT_uncache_enable_reg0	= 0x0;
	HT_uncache_enable_reg1	= 0x0;
	prom_printf("SET HT_DMA CACHED\n");
#endif
#endif /* CONFIG_CPU_LOONGSON3 */
}

void __init prom_free_prom_memory(void)
{
}
