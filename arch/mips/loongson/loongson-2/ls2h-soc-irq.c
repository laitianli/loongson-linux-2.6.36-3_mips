/*
 *
 * BRIEF MODULE DESCRIPTION
 *	LS2H BOARD interrupt/setup routines.
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
#include <asm/delay.h>
#include <asm/bootinfo.h>
#include <asm/io.h>
#include <asm/mipsregs.h>
#include <asm/system.h>
#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>

//#undef DEBUG_IRQ
//#define DEBUG_IRQ
#ifdef DEBUG_IRQ
/* note: prints function name for you */
#define DPRINTK(fmt, args...) printk("%s: " fmt, __FUNCTION__ , ## args)
#else
#define DPRINTK(fmt, args...)
#endif

static struct ls2h_int_ctrl_regs volatile *ls2h_board_hw0_icregs
	= (struct ls2h_int_ctrl_regs volatile *)
#ifdef CONFIG_64BIT
	(CKSEG1ADDR(LS2H_INT_REG_BASE));
#else
	(KSEG1ADDR(LS2H_INT_REG_BASE));
#endif


void ack_ls2h_board_irq(unsigned int irq_nr)
{
	DPRINTK("ack_ls2h_board_irq %d\n", irq_nr);
	irq_nr -= LS2H_IRQ_BASE;
    	(ls2h_board_hw0_icregs+(irq_nr>>5))->int_clr |= (1 << (irq_nr&0x1f));
}

void disable_ls2h_board_irq(unsigned int irq_nr)
{
	DPRINTK("disable_ls2h_board_irq %d\n", irq_nr);
	irq_nr -= LS2H_IRQ_BASE;
    	(ls2h_board_hw0_icregs+(irq_nr>>5))->int_en &= ~(1 << (irq_nr&0x1f));
}

void enable_ls2h_board_irq(unsigned int irq_nr)
{
	DPRINTK("enable_ls2h_board_irq %d\n", irq_nr);
	irq_nr -= LS2H_IRQ_BASE;
    	(ls2h_board_hw0_icregs+(irq_nr>>5))->int_en |= (1 << (irq_nr&0x1f));
}

static void end_ls2h_board_irq(unsigned int irq_nr)
{
	if (!(irq_desc[irq_nr].status & (IRQ_DISABLED|IRQ_INPROGRESS))){
		ack_ls2h_board_irq(irq_nr);
		enable_ls2h_board_irq(irq_nr);
	}
}


static struct irq_chip ls2h_board_irq_chip = {
	.name = "LS2H BOARD",
	.ack = ack_ls2h_board_irq,
	.mask = disable_ls2h_board_irq,
	.mask_ack = disable_ls2h_board_irq,
	.unmask = enable_ls2h_board_irq,
	.eoi = enable_ls2h_board_irq,
	.end = end_ls2h_board_irq,
};

void disable_lpc_irq(unsigned int irq_nr)
{
	int val; 
	DPRINTK("disable_lpc_irq %d\n", irq_nr);
	val = ls2h_readw(LS2H_LPC_CFG1_REG);
	val &= ~(1 << irq_nr);
	ls2h_writew(val, LS2H_LPC_CFG1_REG);
}

void enable_lpc_irq(unsigned int irq_nr)
{
	int val; 
	DPRINTK("enable_lpc_irq %d\n", irq_nr);
	val = ls2h_readw(LS2H_LPC_CFG1_REG);
	val |= (1 << irq_nr);
	ls2h_writew(val, LS2H_LPC_CFG1_REG);
}

static struct irq_chip lpc_irq_chip = {
	.name = "LPC",
	.mask = disable_lpc_irq,
	.unmask = enable_lpc_irq,
	.eoi = enable_lpc_irq,
};
void ls2h_board_hw_irqdispatch(int n)
{
	int irq;
	int intstatus = 0;
   	int status;
	int lpc_irq = 0;
	int lpc_irq_status = 0;

	/* Receive interrupt signal, compute the irq */
	status = read_c0_cause();
	intstatus = (ls2h_board_hw0_icregs+n)->int_isr;
	
	irq=ffs(intstatus);

	if(!irq){
		printk("Unknow n: %d interrupt status %x intstatus %x \n", n, status, intstatus);
		return; 
	}else if ((n==0) && (intstatus & (0x1 << 13)) != 0x0) {
		lpc_irq_status = ls2h_readw(LS2H_LPC_CFG2_REG) & ls2h_readw(LS2H_LPC_CFG1_REG) & 0xfeff;
		if (lpc_irq_status != 0)
			while((lpc_irq = ffs(lpc_irq_status)) != 0x0 ) {
				do_IRQ(lpc_irq-1);
				lpc_irq_status &=  ~(0x1 << (lpc_irq-1));
			}
	}
	else do_IRQ( n*32 + LS2H_IRQ_BASE + irq - 1);
}

void ls2h_board_irq_init(u32 irq_base)
{
	u32 i;
	for (i= irq_base; i<= LS2H_LAST_IRQ; i++) 
		set_irq_chip_and_handler(i, &ls2h_board_irq_chip, handle_level_irq);

	set_irq_chip_and_handler(LS2H_KBD_IRQ, &lpc_irq_chip, handle_level_irq);
	set_irq_chip_and_handler(LS2H_AUX_IRQ, &lpc_irq_chip, handle_level_irq);
}
