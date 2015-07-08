/*
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Copyright (C) 2007 Lemote, Inc. & Institute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
 * Copyright (C) 2009 Lemote, Inc.
 * Author: Zhangjin Wu, wuzhangjin@gmail.com
 */
#include <linux/init.h>
#include <linux/pm.h>

#include <asm/reboot.h>

#include <loongson.h>
extern unsigned long long poweroff_addr;
extern unsigned long long reboot_addr;

#ifdef CONFIG_LOONGSON2H_SOC 
extern void mach_prepare_shutdown(void);
extern void mach_prepare_reboot(void);
#endif

static void loongson_halt(void)
{
	pr_notice("\n\n** You can safely turn off the power now **\n\n");
	while (1) {
		if (cpu_wait)
			cpu_wait();
	}
}

static int __init mips_reboot_setup(void)
{
	_machine_halt = loongson_halt;

#ifndef CONFIG_LOONGSON2H_SOC 
	_machine_restart = (void *)reboot_addr;
	pm_power_off = (void *)poweroff_addr;
#else
	_machine_restart = (void *)mach_prepare_reboot;
	pm_power_off = (void *)mach_prepare_shutdown;
#endif

	return 0;
}



arch_initcall(mips_reboot_setup);
