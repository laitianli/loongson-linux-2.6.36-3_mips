/*
 * fixup-ls2hsoc.c
 *
 * Copyright (C) 2004 ICT CAS
 * Author: Li xiaoyu, ICT CAS
 *   lixy@ict.ac.cn
 *
 * Copyright (C) 2007 Lemote, Inc. & Institute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
 * 
 * Copyright (C) 2010 Dawning 
 * Author: Yongcheng Li, Dawning 
 *    liych@dawning.com.cn
 *
 * Copyright (C) 2010 Dawning 
 * Author: Lv minqiang, Dawning, Inc 
 *    lvmq@dawning.com.cn
 *  Changed for : 
 *		1.addust coding 
 *		2. add sata fixup
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
#include <linux/pci.h>
#include <asm/mips-boards/bonito64.h>
#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>

extern void prom_printf(char *fmt, ...);

#define USE_BIOS_INTERFACE

int __init pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	int pos;
	u16 max_payload_spt, cur_payload_spt, control;

	if (dev->bus->number == 5 || dev->bus->number == 6 || dev->bus->number == 7)
		dev->irq = 117;
	else 
	  dev->irq = (pin - 1) + LS2H_PCIE_PORT0_INTA_IRQ
	    + LS2H_PCIE_GET_PORTNUM(dev->sysdata);

	printk("%s: %d\n",__FILE__, __LINE__);
	printk("dev->irq = %d\n",dev->irq);

	/**
	 * fixup settings of MPS & MRRS during fixing irq 
	 * check whether MPSSPT is smaller than parents',
	 * keep the smaller MPSSPT in the child's register 
	 */
	if (!(dev->bus->parent)) {
		pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
		pci_read_config_word(dev, pos + PCI_EXP_DEVCAP,
				     &max_payload_spt);
		max_payload_spt &= PCI_EXP_DEVCAP_PAYLOAD;
	} else {
		pos = pci_find_capability(dev->bus->self, PCI_CAP_ID_EXP);
		pci_read_config_word(dev->bus->self, pos + PCI_EXP_DEVCAP,
				     &max_payload_spt);
		max_payload_spt &= PCI_EXP_DEVCAP_PAYLOAD;

		pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
		pci_read_config_word(dev, pos + PCI_EXP_DEVCAP,
				     &cur_payload_spt);
		cur_payload_spt &= PCI_EXP_DEVCAP_PAYLOAD;

		if (max_payload_spt > cur_payload_spt)
			max_payload_spt = cur_payload_spt;
	}

	max_payload_spt = 0;

	pci_read_config_word(dev, pos + PCI_EXP_DEVCTL, &control);
	control &= (~PCI_EXP_DEVCTL_PAYLOAD & ~PCI_EXP_DEVCTL_READRQ);
	control |= ((max_payload_spt << 5) | (max_payload_spt << 12));
	pci_write_config_word(dev, pos + PCI_EXP_DEVCTL, control);
	printk("pci %s: set Max_Payload_Size & Max_Read_Request_Size to %03x\n",
	       pci_name(dev), max_payload_spt);

	return dev->irq;

}

/* Do platform specific device initialization at pci_enable_device() time */
int pcibios_plat_dev_init(struct pci_dev *dev)
{
	return 0;
}
