/*
 * fixup-3a780e.c
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

extern void prom_printf(char *fmt, ...);

#define USE_BIOS_INTERFACE
#define show_fixup_info(dev) \
	printk("Fixup: bus(%d) dev(%d) vendor(0x%x) device(0x%x): irq=%d\n",\
				dev->bus->number, PCI_SLOT(dev->devfn),	\
					dev->vendor, dev->device, dev->irq);

int rs780e_pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
#ifndef USE_BIOS_INTERFACE
	if ((dev->bus->number == 7) && (PCI_SLOT(dev->devfn) == 0)) {
		if (dev->vendor == 0x10ec && dev->device == 0x8168) {
			dev->irq = 5;
			(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE,
								dev->irq);
			show_fixup_info(dev);

			return dev->irq;
		}
	} else if ((dev->bus->number == 2) && (PCI_SLOT(dev->devfn) == 0)) {
		dev->irq = 6;
		(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
		show_fixup_info(dev);

		return dev->irq;
	} else if ((dev->bus->number == 3) && (PCI_SLOT(dev->devfn) == 0)) {
		dev->irq = 5;
		(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
		show_fixup_info(dev);

		return dev->irq;
	} else if ((dev->bus->number == 4) && (PCI_SLOT(dev->devfn) == 0)) {
		dev->irq = 3;
		(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
		show_fixup_info(dev);

		return dev->irq;
	} else if ((dev->bus->number == 5) && (PCI_SLOT(dev->devfn) == 0)) {
		dev->irq = 3;
		(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
		show_fixup_info(dev);

		return dev->irq;
	} else if ((dev->bus->number == 10) && (PCI_SLOT(dev->devfn) == 4)) {
		dev->irq = 5;
		(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
		show_fixup_info(dev);

		return dev->irq;
	} else if ((dev->bus->number == 10) && (PCI_SLOT(dev->devfn) == 5)) {
		dev->irq = 5;
		(void) pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
		show_fixup_info(dev);

		return dev->irq;
	} else
		return 0;
#else
	show_fixup_info(dev);
	return dev->irq;
#endif
}

/* Do platform specific device initialization at pci_enable_device() time */
int rs780e_pcibios_plat_dev_init(struct pci_dev *dev)
{
	return 0;
}

#ifndef USE_BIOS_INTERFACE
/*
 * smbus is the system control center in sb700
 */
static void __init godson3a_smbus_fixup(struct pci_dev *pdev)
{
	unsigned short t16;
	unsigned char t8;
	prom_printf("\n-----------------godson3a_smbus_fixup---------------\n");

	/*1. usb interrupt map smbus reg:0XBE  map usbint1map
	 * usbint3map(ohci use) to PCI_INTC# map usbint2map
	 *usbint4map(ehci use) to PCI_INTC#
	 */
	(void) pci_write_config_word(pdev, 0xbe, ((2 << 0) | (2 << 3) |
					(2 << 8) | (2 << 11)));
	pci_read_config_word(pdev, 0xbe, &t16);
	prom_printf(" set smbus reg (0xbe) :%x (usb intr map)\n", t16);

	/*2. sata interrupt map smbus reg:0Xaf map sataintmap to PCI_INTH#*/
	(void) pci_write_config_byte(pdev, 0xaf, 0x7 << 2 );
	pci_read_config_byte(pdev, 0xaf, &t8);
	prom_printf(" set smbus reg (0xaf) :%x (sata intr map)\n", t8);

	/* Set SATA and PATA Controller to combined mode
	 * Port0-Port3 is SATA mode, Port4-Port5 is IDE mode
	 */
	(void) pci_read_config_byte(pdev, 0xad,  &t8);
	t8 |= 0x1<<3;
	t8 &= ~(0x1<<4);
	(void) pci_write_config_byte(pdev, 0xad,  t8);

	/* Map the HDA interrupt to INTE */
	pci_read_config_byte(pdev, 0x63, &t8);
	t8 &= 0xf8;
	pci_write_config_byte(pdev, 0x63, t8 | 0x4);

	/* Set GPIO42, GPIO43, GPIO44, GPIO46 as HD function */
	pci_write_config_word(pdev, 0xf8, 0x0);
	pci_write_config_word(pdev, 0xfc, 0x2<<0);

	/* INTA-->IRQ3: PCIeX1(right) */
	outb(0x0, 0xC00);
	outb(0x3, 0xC01);
	/* INTB-->IRQ3: PCIeX1(left) */
	outb(0x1, 0xC00);
	outb(0x3, 0xC01);
	/* INTF-->IRQ5: PCI(left) */
	outb(0xA, 0xC00);
	outb(0x5, 0xC01);
	/* INTG-->IRQ5: PCI(right) */
	outb(0xB, 0xC00);
	outb(0x5, 0xC01);

	/* INTD-->IRQ5: RTL8111DL */
	/* INTD-->IRQ5: PCIeX8 dev3*/
	outb(0x3, 0xC00);
	outb(0x5, 0xC01);

	/* INTH-->IRQ4: SATA */
	outb(0xC, 0xC00);
	outb(0x4, 0xC01);
	/* INTE-->IRQ5: HDA */
	outb(0x9, 0xC00);
	outb(0x5, 0xC01);
	/* INTC-->IRQ6: USB */
	/* INTC-->IRQ6: PCIeX8 dev2*/
	outb(0x2, 0xC00);
	outb(0x6, 0xC01);

	outw(inw(0x4D0) | (1 << 6) | (1 << 5) | (1 << 4) | (1 << 3), 0x4D0);
}

/* fixup sb700 sata controller configure.
 *  in file "drivers/pci/quirks.c" function quirk_amd_ide_mode do the same job
 */
static void __init godson3a_sata_fixup(struct pci_dev *pdev)
{
	unsigned char t8;
	unsigned int t32;
	prom_printf("\n-----------------godson3a_sata_fixup---------------\n");

	/*1.enable the subcalss code register for setting sata controller mode*/
	pci_read_config_byte(pdev, 0x40, &t8);
	(void) pci_write_config_byte(pdev, 0x40, (t8 | 0x01) );

	/*2.set sata controller act as AHCI mode
	 *	 sata controller support IDE mode, AHCI mode, Raid mode*/
	(void) pci_write_config_byte(pdev, 0x09, 0x01);
	(void) pci_write_config_byte(pdev, 0x0a, 0x06);

	/*3.disable the subcalss code register*/
	pci_read_config_byte(pdev, 0x40, &t8);
	(void) pci_write_config_byte(pdev, 0x40, t8 & (~0x01));

	prom_printf("-----------------tset sata------------------\n");
	pci_read_config_dword(pdev, 0x40, &t32);
	prom_printf("sata pci_config 0x40 (%x)\n", t32);
	pci_read_config_dword(pdev, 0x0, &t32);
	prom_printf("sata pci_config 0x00 (%x)\n", t32);

	pdev->irq = 4;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

static void __init godson3a_ide_fixup(struct pci_dev *pdev)
{
	prom_printf("\n-----------------godson3a_ide_fixup---------------\n");
	/*set IDE ultra DMA enable as master and slalve device*/
	(void) pci_write_config_byte(pdev, 0x54, 0xf);
	/*set ultral DAM mode 0~6  we use 6 as high speed !*/
	(void) pci_write_config_word(pdev, 0x56, (0x6 << 0) | (0x6 << 4) |
						(0x6 << 8) | (0x6 << 12));
}

static void __init godson3a_ohci0_fixup(struct pci_dev *pdev)
{
	pdev->irq = 6;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

static void __init godson3a_ohci1_fixup(struct pci_dev *pdev)
{
	pdev->irq = 6;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

static void __init godson3a_ohci2_fixup(struct pci_dev *pdev)
{
	pdev->irq = 6;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

static void __init godson3a_ehci_fixup(struct pci_dev *pdev)
{
	pdev->irq = 6;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

static void __init godson3a_lpc_fixup(struct pci_dev *pdev)
{
	unsigned char t;

	pci_read_config_byte(pdev, 0x46, &t);
	printk("Fixup: lpc: 0x46 value is 0x%x\n",t);
	pci_write_config_byte(pdev, 0x46, t | (0x3 << 6));
	pci_read_config_byte(pdev, 0x46, &t);

	pci_read_config_byte(pdev, 0x47, &t);
	printk("Fixup: lpc: 0x47 value is 0x%x\n",t);
	pci_write_config_byte(pdev, 0x47, t | 0xff);
	pci_read_config_byte(pdev, 0x47, &t);

	pci_read_config_byte(pdev, 0x48, &t);
	printk("Fixup: lpc: 0x48 value is 0x%x\n",t);
	pci_write_config_byte(pdev, 0x48, t | 0xff);
	pci_read_config_byte(pdev, 0x48, &t);
}

static void __init godson3a_hda_fixup(struct pci_dev *pdev){

	pdev->irq = 5;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

static void __init godson3a_graphic_fixup(struct pci_dev *pdev)
{
	pdev->irq = 6;
	pci_write_config_byte(pdev,PCI_INTERRUPT_LINE,pdev->irq);

	show_fixup_info(dev);
}

DECLARE_PCI_FIXUP_EARLY(0x1002, 0x4385, godson3a_smbus_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x4390, godson3a_sata_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x439c, godson3a_ide_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x4397, godson3a_ohci0_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x4398, godson3a_ohci1_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x4399, godson3a_ohci2_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x4396, godson3a_ehci_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x439d, godson3a_lpc_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x4383, godson3a_hda_fixup);
DECLARE_PCI_FIXUP_FINAL(0x1002, 0x9615, godson3a_graphic_fixup);
#endif

