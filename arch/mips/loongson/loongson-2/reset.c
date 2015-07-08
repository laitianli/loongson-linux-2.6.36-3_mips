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
#include <ls2h/ls2h.h>

void mach_prepare_shutdown(void)
{
	volatile unsigned int * pm_ctrl_reg = (volatile unsigned int *)0xffffffffbfef0014;
	volatile unsigned int * pm_statu_reg = (volatile unsigned int *)0xffffffffbfef000c;
	int temp = 0x10000000;

	* pm_statu_reg = 0x100;	 // clear bit8: PWRBTN_STS
	while(temp != 0)
	  temp--;

	temp =  * pm_statu_reg;
	* pm_ctrl_reg = 0x3c00;  // sleep enable, and enter S5 state 
}

void mach_prepare_reboot(void)
{
	volatile char * hard_reset_reg = (volatile unsigned char *)0xffffffffbfef0030;
	int temp = 0x10000000;

	while(1)
	{
	  * hard_reset_reg = ( * hard_reset_reg) | 0x01; // watch dog hardreset
	  temp = 0x10000000;
	  while(temp != 0)
		temp--;
	  * hard_reset_reg = ( * hard_reset_reg) | 0x01; // watch dog hardreset
	}
}

