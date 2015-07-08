/*
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Copyright (C) 2007 Lemote, Inc. & Institute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
 */

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/reboot.h>
#include <asm/system.h>

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pm.h>
#include <linux/delay.h>

#include <boot_param.h>

extern void _wrmsr(u32 reg, u32 hi, u32 lo);
extern void _rdmsr(u32 reg, u32 *hi, u32 *lo);

extern enum loongson_cpu_type cputype;

static void delay(void)
{
	volatile int i;
	for (i=0; i<0x10000; i++);
}

/* cfg 0: system reboot
 *     1: system halt
 */
static void watchdog_config(u32 cfg)
{
#ifdef CONFIG_32BIT
	unsigned char *watch_dog_base = 0xb8000cd6;
	unsigned char *watch_dog_config = 0xba00a041;
	unsigned char *watch_dog_mem = 0xbe010000;
	unsigned char *reg_cf9 = (unsigned char *)0xb8000cf9;
#else
	unsigned char *watch_dog_base = 0x90000efdfc000cd6;
	unsigned char *watch_dog_config = 0x90000efdfe00a041;
	unsigned int *watch_dog_mem = 0x90000e0000010000;
	unsigned char *reg_cf9 = (unsigned char *)0x90000efdfc000cf9;
#endif
	delay();
	*reg_cf9 = 4;

	/* Enable WatchDogTimer */
	delay();
	*watch_dog_base  = 0x69;
	*(watch_dog_base + 1) = 0x0;

	/* Set WatchDogTimer base address is 0x10000 */
	delay();
	*watch_dog_base = 0x6c;
	*(watch_dog_base + 1) = 0x0;

	delay();
	*watch_dog_base = 0x6d;
	*(watch_dog_base + 1) = 0x0;

	delay();
	*watch_dog_base = 0x6e;
	*(watch_dog_base + 1) = 0x1;

	delay();
	*watch_dog_base = 0x6f;
	*(watch_dog_base + 1) = 0x0;

	delay();
	*watch_dog_config = 0xff;

	/* Set WatchDogTimer to starting */
	delay();
	if (cfg == 0) {
		*watch_dog_mem = 0x01;
	} else if (cfg == 1) {
		*watch_dog_mem = 0x05;
	}
	delay();
	*(watch_dog_mem + 1) = 0x500;
	delay();
	//*watch_dog_mem = 0x85;
	*watch_dog_mem |= 0x80;

}

void mach_prepare_reboot(void)
{
	u32 halt = 0;
	u32 hi, lo;

	if(cputype == Loongson_3A){
		watchdog_config(halt);
		delay();
	}
	if(cputype == Loongson_3B){
		_rdmsr(0xe0000014, &hi, &lo);
		lo |= 0x00000001;
		_wrmsr(0xe0000014, hi, lo);
	}
	printk("Hard reset not take effect!!\n");

	__asm__ __volatile__ (
			".long 0x3c02bfc0\n"
			".long 0x00400008\n"
			:::"v0"
			);
}

void mach_prepare_shutdown(void)
{
	u32 halt = 1;

	if(cputype == Loongson_3A){
		watchdog_config(halt);
	}
	if(cputype == Loongson_3B){
#ifdef CONFIG_32BIT
		u32 base;
#else
		u64 base;
#endif
		u32 hi, lo, val;

		_rdmsr(0x8000000c, &hi, &lo);
#ifdef CONFIG_32BIT
		base = (lo & 0xff00) | 0xbfd00000;
#else
		base = (lo & 0xff00) | 0xffffffffbfd00000ULL;
#endif
		val = *(volatile unsigned int *)(base + 0x04);
		val = (val & ~(1 << (16 + 13))) | (1 << 13);
		delay();
		*(__volatile__ u32 *)(base + 0x04) = val;
		delay();
		val = (val & ~(1 << (13))) | (1 << (16 + 13));
		delay();
		*(__volatile__ u32 *)(base + 0x00) = val;
		delay();
	}
}
