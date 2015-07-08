/*
 * Copyright (C) 2007 Lemote Inc. & Insititute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
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
 *
 */
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/irq_cpu.h>
#include <asm/mipsregs.h>
#include <asm/delay.h>
#include <asm/mips-boards/bonito64.h>
#include <loongson.h>
#include <boot_param.h>
#include "irqregs.h"

#ifdef DEBUG_IRQ
/* note: prints function name for you */
#define DPRINTK(fmt, args...) printk("%s: " fmt, __FUNCTION__ , ## args)
#else
#define DPRINTK(fmt, args...)
#endif

#define LPCBASE 

extern void prom_printf(char *fmt, ...);
extern void loongson3_ipi_interrupt(struct pt_regs *regs);
extern void ls2h_init_irq(void);
extern void rs780e_init_irq(void);
extern enum loongson_cpu_type cputype;
extern unsigned long ht_enable;
extern unsigned long long causef_ip;

unsigned int nr_cpu_handle_int;

DEFINE_RAW_SPINLOCK(ls3alpc_lock);

void disable_ls3alpc_irq(unsigned int irq_nr);
void enable_ls3alpc_irq(unsigned int irq_nr);

#define shutdown_ls3alpc_irq		disable_ls3alpc_irq
#define mask_and_ack_ls3alpc_irq	disable_ls3alpc_irq

static struct irqaction cascade_irqaction = {
	.handler	= no_action,
	.name		= "cascade",
};


static struct irq_chip ls3alpc_irq_chip = {
	.name		= "LS3A LPC",
	.ack		= disable_ls3alpc_irq,
	.mask		= disable_ls3alpc_irq,
	.mask_ack	= disable_ls3alpc_irq,
	.unmask		= enable_ls3alpc_irq,
	.eoi		= enable_ls3alpc_irq,
};

void disable_ls3alpc_irq(unsigned int irq_nr)
{

	unsigned long flags;

	raw_spin_lock_irqsave(&ls3alpc_lock, flags);

	DPRINTK("disable_ls3alpc_irq: cpu =  %d, irq_nr = %08x\n",cpu, irq_nr);

	if (irq_nr != 58) {
		LPC_INT_regs_enable &= ~(0x1 << (irq_nr));
	}

	raw_spin_unlock_irqrestore(&ls3alpc_lock, flags);
}

void enable_ls3alpc_irq(unsigned int irq_nr)
{

	unsigned long flags;

	raw_spin_lock_irqsave(&ls3alpc_lock, flags);

	DPRINTK("enable_ls3alpc_irq: cpu =  %d, irq_nr = %08x\n",cpu, irq_nr);

	if (irq_nr != 58)
		LPC_INT_regs_enable  |= (1 << (irq_nr));

	raw_spin_unlock_irqrestore(&ls3alpc_lock, flags);
}

void (*mach_ip3)();
asmlinkage void mach_irq_dispatch(unsigned int pending)
{
/*
 * CPU interrupts used on Loongson3a:
 *
 *	0 - Software interrupt 0 (unused)
 *	1 - Software interrupt 1 (unused)
 *	2 - CPU UART & LPC
 *	3 - South Bridge i8259(HT South Bridge & PCI South Bridge)
 *	4 - Bonito North Bridge(bonito irq at IP4)
 *	5 - HT devices interrupt
 *	6 - IPI interrupt
 *	7 - Timer and Performance Counter
 */
	unsigned int irq, irqs0;

	if (pending & CAUSEF_IP7) {
		do_IRQ(MIPS_CPU_IRQ_BASE + 7);
#ifdef CONFIG_SMP
	} else if (pending & CAUSEF_IP6 /* 0x4000 */){  //smp ipi
		loongson3_ipi_interrupt(NULL);
#endif
	} else if (pending & CAUSEF_IP2) { // For LPC
#ifdef CONFIG_CPU_UART
		if (board_type == LS2H) {
			irqs0 = LPC_INT_regs_enable & LPC_INT_regs_status & 0xfeff;
			if (irqs0 != 0)
			while ((irq = ffs(irqs0)) != 0) {
				do_IRQ(irq-1);
				irqs0 &= ~(1<<(irq-1));
			}
			else
				do_IRQ(MIPS_CPU_IRQ_BASE + 2);
		} else {
				do_IRQ(MIPS_CPU_IRQ_BASE + 2);
		}
#endif
	} else if (pending & CAUSEF_IP3) {
		mach_ip3();
	} else {
		prom_printf("spurious interrupt\n");
		spurious_interrupt();
	}
}

void __init mach_init_irq(void)
{
	/*
	 * init all controller
	 * 0-15   ----> i8259 interrupt(south bridge i8259)
	 * 16-31  ----> loongson cpu interrupt
	 * 32-55  ----> bonito north bridge irq
	 * 56-63  ----> mips cpu interrupt
	 * 64-319 ----> ht devices interrupt
	 */
	if(nr_cpu_loongson < 4)
		nr_cpu_handle_int = nr_cpu_loongson;
	else
		nr_cpu_handle_int = 4;
	/*
	 * Clear all of the interrupts while we change the able around a bit.
	 * int-handler is not on bootstrap
	 */
	clear_c0_status(ST0_IM | ST0_BEV);
	local_irq_disable();

	switch(board_type){
		case LS2H:
			ls2h_init_irq();
			break;
		case RS780E:
		default:
			rs780e_init_irq();
	};
	/* enable south chip irq */
	set_c0_status(STATUSF_IP3);

	/* cascade irq not used at this moment */
	setup_irq(56 + 3, &cascade_irqaction);

	/* enable IPI interrupt */
	set_c0_status(STATUSF_IP6);

	/* Route the LPC interrupt to Core0 INT0 */
	INT_router_regs_lpc_int = 0x11;
	/* Enable LPC interrupts for CPU UART */
	IO_control_regs_Intenset = (0x1<<10);

	/* added for KBC attached on ls3 LPC controler  */
	if (board_type == LS2H) {
		set_irq_chip_and_handler(1 , &ls3alpc_irq_chip, handle_level_irq);
		set_irq_chip_and_handler(12 , &ls3alpc_irq_chip, handle_level_irq);

		/* Enable the LPC interrupt */
		LPC_INT_regs_ctrl = 0x80000000;
		/* set the 18-bit interrpt enable bit for keyboard and mouse */ 
		LPC_INT_regs_enable = (0x1 << 0x1 | 0x1 << 12);
		/* clear all 18-bit interrpt bit */ 
		LPC_INT_regs_clear = 0x3ffff;
	}

	set_irq_chip_and_handler(MIPS_CPU_IRQ_BASE + 2, &ls3alpc_irq_chip,
		handle_level_irq);

	/* enable serial and lpc port irq */
	set_c0_status(STATUSF_IP2);

	prom_printf("init_IRQ done\n");
}
