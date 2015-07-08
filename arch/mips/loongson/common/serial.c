/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 Ralf Baechle (ralf@linux-mips.org)
 *
 * Copyright (C) 2009 Lemote, Inc.
 * Author: Yan hua (yanhua@lemote.com)
 * Author: Wu Zhangjin (wuzhangjin@gmail.com)
 */

#include <linux/io.h>
#include <linux/init.h>
#include <linux/serial_8250.h>

#include <asm/bootinfo.h>

#include <loongson.h>
#include <machine.h>

#define UART_CLK_25M		25000000
#define UART_CLK_33M		33000000
#define UART_CLK_CPU_LPC	368640
#define PORT(int)			\
{								\
	.irq		= int,					\
	.uartclk	= 1843200,				\
	.iotype		= UPIO_PORT,				\
	.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,	\
	.regshift	= 0,					\
}

#define PORT_M(int)				\
{								\
	.irq		= MIPS_CPU_IRQ_BASE + (int),		\
	.uartclk	= 3686400,				\
	.iotype		= UPIO_MEM,				\
	.membase	= (void __iomem *)NULL,			\
	.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,	\
	.regshift	= 0,					\
}

#define PORT_LOONGSON3(mem_base, map_base, uart_clk)	\
{								\
	.irq		= 58,					\
	.uartclk	= uart_clk,				\
	.iotype		= UPIO_MEM,				\
	.membase	= (void *)mem_base,				\
	.mapbase	= map_base,				\
	.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST	\
					| UPF_FIXED_TYPE,	\
	.regshift	= 0,					\
	.type		= PORT_16550A,				\
}

static struct plat_serial8250_port uart8250_data[][2] = {
	[MACH_LOONGSON_UNKNOWN]	{},
	[MACH_LEMOTE_FL2E]	{PORT(4), {} },
	[MACH_LEMOTE_FL2F]	{PORT(3), {} },
	[MACH_LEMOTE_ML2F7]	{PORT_M(3), {} },
	[MACH_LEMOTE_YL2F89]	{PORT_M(3), {} },
	[MACH_DEXXON_GDIUM2F10]	{PORT_M(3), {} },
	[MACH_LEMOTE_NAS]	{PORT_M(3), {} },
	[MACH_LEMOTE_LL2F]	{PORT(3), {} },
	[MACH_LOONGSON3]	{
#ifdef CONFIG_CPU_UART
		PORT_LOONGSON3(CPU_UART0_MEM_BASE, CPU_UART0_MAP_BASE,
							UART_CLK_33M),
		PORT_LOONGSON3(CPU_UART1_MEM_BASE, CPU_UART1_MAP_BASE,
							UART_CLK_33M),
#else
		PORT_LOONGSON3(CPU_LPC_UART_MEM_BASE, CPU_LPC_UART_MAP_BASE,
							UART_CLK_CPU_LPC),
#endif
				},
	[MACH_LOONGSON_END]	{},
};

static struct platform_device uart8250_device = {
	.name = "serial8250",
	.id = PLAT8250_DEV_PLATFORM,
};

static int __init serial_init(void)
{
	uart8250_device.dev.platform_data = uart8250_data[mips_machtype];

	return platform_device_register(&uart8250_device);
}

#ifndef CONFIG_CPU_LOONGSON2H
arch_initcall(serial_init);
#endif
