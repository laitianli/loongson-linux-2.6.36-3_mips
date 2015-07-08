/*
 * Copyright (C) 2000 RidgeRun, Inc.
 * Author: RidgeRun, Inc.
 *   glonnon@ridgerun.com, skranz@ridgerun.com, stevej@ridgerun.com
 *
 * Copyright 2001 MontaVista Software Inc.
 * Author: Jun Sun, jsun@mvista.com or jsun@junsun.net
 * Copyright (C) 2000, 2001 Ralf Baechle (ralf@gnu.org)
 * Copyright (C) 2003 ICT CAS (guoyi@ict.ac.cn)
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
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/irq.h>
#include <linux/ptrace.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/irq_cpu.h>
#include <asm/mipsregs.h>
#include <asm/system.h>
#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>

static struct ls2h_int_ctrl_regs volatile *ls2h_board_hw0_icregs
	= (struct ls2h_int_ctrl_regs volatile *)
#ifdef CONFIG_64BIT
	(CKSEG1ADDR(LS2H_INT_REG_BASE));
#else
	(KSEG1ADDR(LS2H_INT_REG_BASE));
#endif

void ls2h_board_hw_irqdispatch(int n);
void ls2h_board_irq_init(u32 irq_base);

asmlinkage void mach_irq_dispatch(unsigned int pending)
{
	if (pending & CAUSEF_IP7) {
		do_IRQ(MIPS_CPU_IRQ_BASE+7);
        }
    	else if (pending & CAUSEF_IP2) {
       		ls2h_board_hw_irqdispatch(0);
	}
    	else if (pending & CAUSEF_IP3) {
       		ls2h_board_hw_irqdispatch(1);
	}
	else if (pending & CAUSEF_IP4) {
		ls2h_board_hw_irqdispatch(2);
	}
	else if (pending & CAUSEF_IP5) {
		ls2h_board_hw_irqdispatch(3);
	}
	else if (pending & CAUSEF_IP6) {
		ls2h_board_hw_irqdispatch(4);
	} else {
		spurious_interrupt();
	}

}

static struct irqaction cascade_irqaction = {
	.handler	= no_action,
	.name		= "cascade",
};

void __init mach_init_irq(void)
{
	int i;

	clear_c0_status(ST0_IM | ST0_BEV);
	local_irq_disable();

	/* uart, keyboard, and mouse are active high */
	(ls2h_board_hw0_icregs+0)->int_edge = 0x00000000;
	(ls2h_board_hw0_icregs+0)->int_pol = 0xff7fffff;
	(ls2h_board_hw0_icregs+0)->int_clr= 0x00000000;
	(ls2h_board_hw0_icregs+0)->int_en = 0x00ffffff;

	(ls2h_board_hw0_icregs+1)->int_edge = 0x00000000;
	(ls2h_board_hw0_icregs+1)->int_pol = 0xfeffffff;
	(ls2h_board_hw0_icregs+1)->int_clr = 0x00000000;
	(ls2h_board_hw0_icregs+1)->int_en = 0x03ffffff;

	(ls2h_board_hw0_icregs+2)->int_edge = 0x00000000;
	(ls2h_board_hw0_icregs+2)->int_pol = 0xffffffff;
	(ls2h_board_hw0_icregs+2)->int_clr = 0x00000000;
	(ls2h_board_hw0_icregs+2)->int_en = 0x00000000;

	ls2h_board_irq_init(LS2H_IRQ_BASE);
	mips_cpu_irq_init();	
	setup_irq(MIPS_CPU_IRQ_BASE + 2, &cascade_irqaction);
	setup_irq(MIPS_CPU_IRQ_BASE + 3, &cascade_irqaction);
	setup_irq(MIPS_CPU_IRQ_BASE + 4, &cascade_irqaction);
	setup_irq(MIPS_CPU_IRQ_BASE + 5, &cascade_irqaction);
	setup_irq(MIPS_CPU_IRQ_BASE + 6, &cascade_irqaction);

	set_c0_status(STATUSF_IP2 | STATUSF_IP3 | STATUSF_IP4 | STATUSF_IP5 | STATUSF_IP7);
}
