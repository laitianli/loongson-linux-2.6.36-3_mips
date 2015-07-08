/*
 * ops-loongson3a.c
 *
 * Copyright (C) 2004 ICT CAS
 * Author: Li xiaoyu, ICT CAS
 *   lixy@ict.ac.cn
 *
 * Copyright (C) 2007 Lemote, Inc. & Institute of Computing Technology
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

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kernel.h>

#include <asm/mips-boards/bonito64.h>

#define PCI_ACCESS_READ		0
#define PCI_ACCESS_WRITE	1
extern int pcidev_max_func_num;

static inline void bflush(void)
{
	/* flush Bonito register writes */
	(void)BONITO_PCICMD;
}

#define HT1LO_PCICFG_BASE      0x1a000000
#define HT1LO_PCICFG_BASE_TP1  0x1b000000
static int loongson3_pci_config_access(unsigned char access_type,
				  struct pci_bus *bus, unsigned int devfn,
				  int where, u32 *data)
{
	unsigned char busnum = bus->number;
	
	u_int64_t addr, type;
	void *addrp;
	int device = devfn >> 3;
	int function = devfn & 0x7;
	int reg = where & ~3;

	if (busnum == 0) {
		/* Type 0 configuration on onboard PCI bus */
		if (device > 31 || function > pcidev_max_func_num) {
				*data = -1;	/* device out of range */
				return PCIBIOS_DEVICE_NOT_FOUND;
		}
		addr = (device << 11) | (function << 8) | reg;
		type = 0;
		//addrp = (void *)CKSEG1ADDR(HT1LO_PCICFG_BASE | (addr & 0xffff));
		addrp = (void *)(UNCAC_BASE|(HT1LO_PCICFG_BASE | (addr & 0xffff)));
	} else {
			/* Type 1 configuration on offboard PCI bus */
			if (busnum > 255 || device > 31 || function > pcidev_max_func_num) {
				*data = -1;	/* device out of range */
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		addr = (busnum << 16) | (device << 11) | (function << 8) | reg;
		type = 0x10000;
		addrp = (void *)(UNCAC_BASE | (HT1LO_PCICFG_BASE_TP1 | (addr)));
	}

	/* clear aborts */
	if (access_type == PCI_ACCESS_WRITE){
		*(volatile unsigned int *)addrp = cpu_to_le32(*data);
	} else {
		*data = le32_to_cpu(*(volatile unsigned int *)addrp);
		if (*data == 0xffffffff){
			*data = -1;
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
	}

	return PCIBIOS_SUCCESSFUL;
}

static int loongson3_pci_pcibios_read(struct pci_bus *bus, unsigned int devfn,
				 int where, int size, u32 * val)
{
	u32 data = 0;

	int ret = loongson3_pci_config_access(PCI_ACCESS_READ,
			bus, devfn, where, &data);

	if (ret != PCIBIOS_SUCCESSFUL)
		return ret;

	if (size == 1)
		*val = (data >> ((where & 3) << 3)) & 0xff;
	else if (size == 2)
		*val = (data >> ((where & 3) << 3)) & 0xffff;
	else
		*val = data;

	return PCIBIOS_SUCCESSFUL;
}

static int loongson3_pci_pcibios_write(struct pci_bus *bus, unsigned int devfn,
					int where, int size, u32 val)
{
	u32 data = 0;
	int ret;

	if (size == 4)
		data = val;
	else {
		ret = loongson3_pci_config_access(PCI_ACCESS_READ,
				bus, devfn, where, &data);
		if (ret != PCIBIOS_SUCCESSFUL)
			return ret;

		if (size == 1)
			data = (data & ~(0xff << ((where & 3) << 3))) |
				(val << ((where & 3) << 3));
		else if (size == 2)
			data = (data & ~(0xffff << ((where & 3) << 3))) |
				(val << ((where & 3) << 3));
	}

	ret = loongson3_pci_config_access(PCI_ACCESS_WRITE,
			bus, devfn, where, &data);
	if (ret != PCIBIOS_SUCCESSFUL)
		return ret;

	return PCIBIOS_SUCCESSFUL;
}

void _rdmsr(u32 msr, u32 *hi, u32 *lo)
{
	struct pci_bus bus = {
		.number = 0
	};
	u32 devfn = PCI_DEVFN(14, 0);
	loongson3_pci_pcibios_write(&bus, devfn, 0xf4, 4, msr);
	loongson3_pci_pcibios_read(&bus, devfn, 0xf8, 4, lo);
	loongson3_pci_pcibios_read(&bus, devfn, 0xfc, 4, hi);
	//printk("rdmsr msr %x, lo %x, hi %x\n", msr, *lo, *hi);
}

void _wrmsr(u32 msr, u32 hi, u32 lo)
{
	struct pci_bus bus = {
		.number = 0
	};
	u32 devfn = PCI_DEVFN(14, 0);
	loongson3_pci_pcibios_write(&bus, devfn, 0xf4, 4, msr);
	loongson3_pci_pcibios_write(&bus, devfn, 0xf8, 4, lo);
	loongson3_pci_pcibios_write(&bus, devfn, 0xfc, 4, hi);
	//printk("wrmsr msr %x, lo %x, hi %x\n", msr, lo, hi); 
}

struct pci_ops loongson_pci_ops = {
	.read = loongson3_pci_pcibios_read,
	.write = loongson3_pci_pcibios_write
};
