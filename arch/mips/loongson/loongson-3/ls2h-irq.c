/*
 *
 * BRIEF MODULE DESCRIPTION
 *	LS1GP BOARD interrupt/setup routines.
 *
 * Copyright 2000,2001 MontaVista Software Inc.
 * Author: MontaVista Software, Inc.
 *         	ppopov@mvista.com or source@mvista.com
 *
 * Part of this file was derived from Carsten Langgaard's 
 * arch/mips/ite-boards/generic/init.c.
 *
 * Carsten Langgaard, carstenl@mips.com
 * Copyright (C) 1999,2000 MIPS Technologies, Inc.  All rights reserved.
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/timex.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/serial_reg.h>

#include <asm/bitops.h>
#include <asm/bootinfo.h>
#include <asm/io.h>
#include <asm/mipsregs.h>
#include <asm/system.h>

#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>
#include "irqregs.h"

extern void prom_printf(char *fmt, ...);
extern void mips_cpu_irq_init(void);

#ifdef DEBUG_IRQ
/* note: prints function name for you */
#define DPRINTK(fmt, args...) printk("%s: " fmt, __FUNCTION__ , ## args)
#else
#define DPRINTK(fmt, args...)
#endif

#ifdef CONFIG_REMOTE_DEBUG
extern void breakpoint(void);
#endif

DEFINE_RAW_SPINLOCK(ls2hirq_lock);

void disable_ls2h_irq(unsigned int irq_nr);
void enable_ls2h_irq(unsigned int irq_nr);


static struct ls2h_int_ctrl_regs volatile *ls2h_hw0_icregs
#ifdef CONFIG_64BIT
	= (struct ls2h_int_ctrl_regs volatile *)(CKSEG1ADDR(LS2H_INT_REG_BASE));
#else 
	= (struct ls2h_int_ctrl_regs volatile *)(KSEG1ADDR(LS2H_INT_REG_BASE));
#endif

void disable_ls2h_irq(unsigned int irq_nr)
{

	unsigned long flags;
	raw_spin_lock_irqsave(&ls2hirq_lock, flags);

	DPRINTK("disable_ls2h_irq %d\n", irq_nr);
		irq_nr -=  LS2H_IRQ_BASE;
	(ls2h_hw0_icregs+(irq_nr>>5))->int_en &= ~(1 << (irq_nr&0x1f));

	raw_spin_unlock_irqrestore(&ls2hirq_lock, flags);
}

void enable_ls2h_irq(unsigned int irq_nr)
{

	unsigned long flags;
	raw_spin_lock_irqsave(&ls2hirq_lock, flags);
	DPRINTK("enable_ls2h_irq %d\n", irq_nr);
	irq_nr -=  LS2H_IRQ_BASE;
	(ls2h_hw0_icregs+(irq_nr>>5))->int_en |= (1 << (irq_nr&0x1f));

	raw_spin_unlock_irqrestore(&ls2hirq_lock, flags);
}



#define shutdown_ls2h_irq	disable_ls2h_irq
#define mask_and_ack_ls2h_irq	disable_ls2h_irq


static void end_ls2h_irq(unsigned int irq)
{
	if (!(irq_desc[irq].status & (IRQ_DISABLED|IRQ_INPROGRESS))){
		(ls2h_hw0_icregs+((irq- LS2H_IRQ_BASE)>>5))->int_clr |= 1 << (irq&0x1f); 
		if(irq<LS2H_GPIO_FIRST_IRQ) 
			enable_ls2h_irq(irq);
	}
}


static struct irq_chip ls2h_irq_chip = {
	.name		= "LS2H BOARD",
	.ack		= disable_ls2h_irq,
	.mask		= disable_ls2h_irq,
	.mask_ack	= disable_ls2h_irq,
	.unmask		= enable_ls2h_irq,
	.eoi		= enable_ls2h_irq,
	.end		= end_ls2h_irq,
};

void ls2h_irq_dispatch(int n)
{
	int irq;
	int intstatus = 0;

	/* Receive interrupt signal, compute the irq */
	intstatus = (ls2h_hw0_icregs+n)->int_isr;
	
	irq = ffs(intstatus);
	
	if (!irq) {
		printk("Unknow interrupt intstatus %x \n",intstatus);
		return; 
	} else if(n == 1 && irq == 11) {
		n = n;
	} else {
		do_IRQ(n*32+irq-1 + LS2H_IRQ_BASE);
	} 
}

void mach_ls2h_irq()
{
	unsigned int intstatus,i;
	
	for ( i = 0; i < 5; i++)
		if ((intstatus = (ls2h_hw0_icregs + i)->int_isr) != 0)
			ls2h_irq_dispatch(i);
}

extern void (*mach_ip3) (int cpu);
void ls2h_init_irq(void)
{

	u32 i,t;

	clear_c0_status(ST0_IM | ST0_BEV);
	local_irq_disable();

	/*  Route INTn0 to IP3 */
	INT_router_regs_sys_int0 = 0x21;

	/* Enable the IO interrupt controller */ 
	t = IO_control_regs_Inten; 
	prom_printf("the old IO inten is %x\n", t);
	IO_control_regs_Intenset = t | (0xffff << 16) | (0x1 << 10) | (0x1 << 0);
	t = IO_control_regs_Inten;
	prom_printf("the new IO inten is %x\n", t);

	/* Sets the first-level interrupt dispatcher. */
	mips_cpu_irq_init();
	/*
	 * loongson2h chip_config0
	 * bit[5]:loongson2h bridge model enable. 1:enable  0:disable
	 */
	t = *(volatile unsigned int *)CKSEG1ADDR(LS2H_CHIP_CFG0_REG);
	t |= 0x1<<5;
	*(volatile unsigned int *)CKSEG1ADDR(LS2H_CHIP_CFG0_REG) = t;
	for(i=0;i<5;i++){
		/* active level setting */
		(ls2h_hw0_icregs+i)->int_pol = -1;
		/* make all interrupts level triggered */
		(ls2h_hw0_icregs+i)->int_edge = 0x00000000;
		/* clear all interrupts */
		(ls2h_hw0_icregs+i)->int_clr = 0xffffffff;
	}

	for (i = LS2H_IRQ_BASE; i<= LS2H_LAST_IRQ; i++) 
		set_irq_chip_and_handler(i , &ls2h_irq_chip, handle_level_irq);

	mach_ip3 = mach_ls2h_irq;
}
