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
#include <htregs.h>
#include <linux/cpumask.h>
#include <asm/smp.h>
#include <boot_param.h>
#include "irqregs.h"
#ifdef CONFIG_I8259
#include <asm/i8259.h>
#endif

extern void prom_printf(char *fmt, ...);
extern void loongson3_ipi_interrupt(struct pt_regs *regs);
extern int loongson3_send_irq_by_ipi(int cpu,int irqs);
extern unsigned long ht_enable;
extern unsigned long long causef_ip;
extern unsigned long phy_core_id[];
extern unsigned int nr_cpu_loongson;
extern void (*mach_ip3)();

/*
 * get the irq via the HT irq vector registers.
 */
static int mach_ht_irq(void)
{
	int irq, isr;

	irq = -1;

	if ((IO_control_regs_Intisr & IO_control_regs_Inten) & 0x1000000) {
		isr = HT_irq_vector_reg0 & HT_irq_enable_reg0;
		irq = ffs(isr) - 1;
		HT_irq_vector_reg0 = 1 << irq;
	}

	return irq;
}
EXPORT_SYMBOL(mach_ht_irq);

static void dispatch_ht_irq(void)
{
	int irq;
//#ifdef HT_SOUTH_BRIDGE_I8259
#if 1
	irq = mach_ht_irq();
#else
	irq = mach_i8259_irq();
#endif
	if (irq >= 0)
        {
		do_IRQ(irq);
	}
	else
		spurious_interrupt();
}

void rs780e_init_irq(void)
{

	/* Route the HT interrupt to Core0 INT1 */
	INT_router_regs_HT1_int0 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int1 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int2 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int3 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int4 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int5 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int6 = 0x20 | (1 << phy_core_id[0]);
	INT_router_regs_HT1_int7 = 0x20 | (1 << phy_core_id[0]);
	/* Enable the all HT interrupt */
	HT_irq_enable_reg0 = 0x0000ffff;
	HT_irq_enable_reg1 = 0x00000000;
	HT_irq_enable_reg2 = 0x00000000;
	HT_irq_enable_reg3 = 0x00000000;
	HT_irq_enable_reg4 = 0x00000000;
	HT_irq_enable_reg5 = 0x00000000;
	HT_irq_enable_reg6 = 0x00000000;
	HT_irq_enable_reg7 = 0x00000000;

	/* Enable the IO interrupt controller */ 
	IO_control_regs_Intenset = IO_control_regs_Inten | (0xffff << 16);
	prom_printf("the new IO inten is %x\n", IO_control_regs_Inten);

	/* Sets the first-level interrupt dispatcher. */
	mips_cpu_irq_init();	

#ifdef CONFIG_I8259
	init_i8259_irqs();
#endif
	set_c0_status(STATUSF_IP6);
	mach_ip3 = dispatch_ht_irq;
}
