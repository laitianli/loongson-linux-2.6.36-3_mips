/*
 * Copyright (C) 2009 Lemote Inc.
 * Author: Wu Zhangjin, wuzhangjin@gmail.com
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <asm/bootinfo.h>
#include <asm/addrspace.h>

#include <loongson.h>
#include <ls2h/ls2h.h>

/* ioremapped */
#ifdef CONFIG_CPU_LOONGSON3
#ifdef CONFIG_CPU_UART
unsigned long _loongson_uart_base = 0x900000001fe001e0;
#else
unsigned long _loongson_uart_base = 0x900000001ff003f8;
#endif
#endif
#ifdef CONFIG_CPU_LOONGSON2H
unsigned long _loongson_uart_base = CKSEG1ADDR(LS2H_UART0_REG_BASE);
#endif
EXPORT_SYMBOL(_loongson_uart_base);
/* raw */
unsigned long loongson_uart_base;
EXPORT_SYMBOL(loongson_uart_base);

void prom_init_loongson_uart_base(void)
{
	switch (mips_machtype) {
	case MACH_LOONGSON3:
		loongson_uart_base = LOONGSON_UART_BASE;
		break;
	case MACH_LOONGSON2H:
		loongson_uart_base = LS2H_UART0_REG_BASE;
		break;
	case MACH_LEMOTE_FL2E:
		loongson_uart_base = LOONGSON_PCIIO_BASE + 0x3f8;
		break;
	case MACH_LEMOTE_FL2F:
	case MACH_LEMOTE_LL2F:
		loongson_uart_base = LOONGSON_PCIIO_BASE + 0x2f8;
		break;
	case MACH_LEMOTE_ML2F7:
	case MACH_LEMOTE_YL2F89:
	case MACH_DEXXON_GDIUM2F10:
	case MACH_LEMOTE_NAS:
	default:
		/* The CPU provided serial port */
		loongson_uart_base = LOONGSON_LIO1_BASE + 0x3f8;
		break;
	}

	_loongson_uart_base =
		(unsigned long)ioremap_nocache(loongson_uart_base, 8);
}
