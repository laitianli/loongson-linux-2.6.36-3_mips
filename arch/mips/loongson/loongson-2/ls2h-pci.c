/*
 * pci.c
 *
 * Copyright (C) 2004 ICT CAS
 * Author: Lin Wei, ICT CAS
 *   wlin@ict.ac.cn
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
#include <linux/init.h>

#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>

extern struct pci_ops ls2h_pci_ops_port0;
extern struct pci_ops ls2h_pci_ops_port1;
extern struct pci_ops ls2h_pci_ops_port2;
extern struct pci_ops ls2h_pci_ops_port3;

//PCI-E controller0 TODO:x4 can't use whole memory space
static struct resource ls2h_pcie_mem_resource0 = {
	.name	= "LS2H PCIE0 MEM",
	.start	= 0x10000000UL,
	.end	= 0x11ffffffUL,
	.flags	= IORESOURCE_MEM,
};

static struct resource ls2h_pcie_io_resource0 = {
	.name	= "LS2H PCIE0 IO MEM",
	.start	= 0x18100000UL,
	.end	= 0x1810ffffUL,
	.flags	= IORESOURCE_IO,
};

static struct pci_controller ls2h_pcie_controller0 = {
	.pci_ops	= &ls2h_pci_ops_port0,
	.io_resource	= &ls2h_pcie_io_resource0,
	.mem_resource	= &ls2h_pcie_mem_resource0,
	.mem_offset	= 0x00000000UL,
	.io_offset	= 0x00000000UL,
	.io_map_base	= 0x00000000UL,
};


//PCI-E controller1
static struct resource ls2h_pcie_mem_resource1 = {
	.name	= "LS2H PCIE1 MEM",
	.start	= 0x12000000UL,
	.end	= 0x13ffffffUL,
	.flags	= IORESOURCE_MEM,
};

static struct resource ls2h_pcie_io_resource1 = {
	.name	= "LS2H PCIE1 IO MEM",
	.start	= 0x18500000UL,
	.end	= 0x1850ffffUL,
	.flags	= IORESOURCE_IO,
};

static struct pci_controller ls2h_pcie_controller1 = {
	.pci_ops	= &ls2h_pci_ops_port1,
	.io_resource	= &ls2h_pcie_io_resource1,
	.mem_resource	= &ls2h_pcie_mem_resource1,
	.mem_offset	= 0x00000000UL,
	.io_offset	= 0x00000000UL,
	.io_map_base	= 0x00000000UL,
};


//PCI-E controller2
static struct resource ls2h_pcie_mem_resource2 = {
	.name	= "LS2H PCIE2 MEM",
	.start	= 0x14000000UL,
	.end	= 0x15ffffffUL,
	.flags	= IORESOURCE_MEM,
};

static struct resource ls2h_pcie_io_resource2 = {
	.name	= "LS2H PCIE2 IO MEM",
	.start	= 0x18900000UL,
	.end	= 0x1890ffffUL,
	.flags	= IORESOURCE_IO,
};

static struct pci_controller ls2h_pcie_controller2 = {
	.pci_ops	= &ls2h_pci_ops_port2,
	.io_resource	= &ls2h_pcie_io_resource2,
	.mem_resource	= &ls2h_pcie_mem_resource2,
	.mem_offset	= 0x00000000UL,
	.io_offset	= 0x00000000UL,
	.io_map_base	= 0x00000000UL,
};


//PCI-E controller3
static struct resource ls2h_pcie_mem_resource3 = {
	.name	= "LS2H PCIE3 MEM",
	.start	= 0x16000000UL,
	.end	= 0x17ffffffUL,
	.flags	= IORESOURCE_MEM,
};

static struct resource ls2h_pcie_io_resource3 = {
	.name	= "LS2H PCIE3 IO MEM",
	.start	= 0x18d00000UL,
	.end	= 0x18d0ffffUL,
	.flags	= IORESOURCE_IO,
};

static struct pci_controller ls2h_pcie_controller3 = {
	.pci_ops	= &ls2h_pci_ops_port3,
	.io_resource	= &ls2h_pcie_io_resource3,
	.mem_resource	= &ls2h_pcie_mem_resource3,
	.mem_offset	= 0x00000000UL,
	.io_offset	= 0x00000000UL,
	.io_map_base	= 0x00000000UL,
};

#ifdef CONFIG_LOAD_PCICFG
#include "pciload.c"
#endif

#ifdef CONFIG_DISABLE_PCI
static int disablepci=1;
#else
static int disablepci=0;
#endif

int ls2h_pcibios_init(void)
{
	extern int pci_probe_only;
	void *addrp;
	u32 data, data1;

	pci_probe_only = 0; //not auto assign the resource 

	if(!disablepci)
{
	//TODO
	ioport_resource.end = 0xffffffff;	//extend iomap
	//TODO
#if 0
	*((volatile unsigned long long int *)CKSEG1ADDR(0xbbd80400)) = *((volatile unsigned long long int *)CKSEG1ADDR(0xbbd80100));
	*((volatile unsigned long long int *)CKSEG1ADDR(0xbbd80440)) = *((volatile unsigned long long int *)CKSEG1ADDR(0xbbd80140));
	*((volatile unsigned long long int *)CKSEG1ADDR(0xbbd80480)) = *((volatile unsigned long long int *)CKSEG1ADDR(0xbbd80180));
#else
	*((volatile unsigned long long int *)CKSEG1ADDR(LS2H_M4_WIN0_BASE_REG)) = 0x0000000080000000;
	*((volatile unsigned long long int *)CKSEG1ADDR(LS2H_M4_WIN0_MASK_REG)) = 0xffffffffc0000000; // only for 1G pci dma now
	*((volatile unsigned long long int *)CKSEG1ADDR(LS2H_M4_WIN0_MMAP_REG)) = 0x00000000800000f3;
#endif


	printk("arch_initcall:ls2h_pcibios_init\n");
	printk("register_pci_controller : %p\n",&ls2h_pcie_controller0);
	//TODO: rewrite to init function
	//Enable ref_clock on PCIE slot0/1/2/3
	addrp = (void *)CKSEG1ADDR(LS2H_CHIP_CFG_REG_BASE
				| LS2H_CHIP_CFG_REG_CLK_CTRL3);
	data = le32_to_cpu(*(volatile unsigned int *)addrp);
	data |= (LS2H_CLK_CTRL3_BIT_PEREF_EN(0)
		| LS2H_CLK_CTRL3_BIT_PEREF_EN(1)
		| LS2H_CLK_CTRL3_BIT_PEREF_EN(2)
		| LS2H_CLK_CTRL3_BIT_PEREF_EN(3));
	*(volatile unsigned int *)addrp = cpu_to_le32(data);

	//Need to wait LTSSM link up?

	//Enable LTSSM & Register controller in RC mode
	addrp = (void *)CKSEG1ADDR(LS2H_PCIE_REG_BASE_PORT(0)
					| LS2H_PCIE_PORT_REG_CTR_STAT);
	data = le32_to_cpu(*(volatile unsigned int *)addrp);

	if (data & LS2H_PCIE_REG_CTR_STAT_BIT_ISRC) {
		//enable LTSSM of port0
		addrp = (void *)CKSEG1ADDR(LS2H_PCIE_REG_BASE_PORT(0)
						| LS2H_PCIE_PORT_REG_CTR0);
		*(volatile unsigned int *)addrp = cpu_to_le32(0xff204c);
		//modify PCI class of port0
		addrp = (void *)CKSEG1ADDR(LS2H_PCIE_PORT_HEAD_BASE_PORT(0)
						| PCI_CLASS_REVISION);
		data1 = le32_to_cpu(*(volatile unsigned int *)addrp);
		data1 &= 0x0000ffff;
		data1 |= (PCI_CLASS_BRIDGE_PCI << 16);
		*(volatile unsigned int *)addrp = cpu_to_le32(data1);

		if (data & LS2H_PCIE_REG_CTR_STAT_BIT_ISX4) {
			//Only Enable & Register controller0 in X4 mode
			register_pci_controller(&ls2h_pcie_controller0);
		}
		else {
			//Enable & Register controller0/1/2/3 in X1 mode
			register_pci_controller(&ls2h_pcie_controller0);

			//enable LTSSM of port1
			addrp = (void *)CKSEG1ADDR(LS2H_PCIE_REG_BASE_PORT(1)
						| LS2H_PCIE_PORT_REG_CTR0);
			*(volatile unsigned int *)addrp = cpu_to_le32(0xff204c);
			//modify PCI class of port1
			addrp = (void *)CKSEG1ADDR(LS2H_PCIE_PORT_HEAD_BASE_PORT(1)
						| PCI_CLASS_REVISION);
			data1 = le32_to_cpu(*(volatile unsigned int *)addrp);
			data1 &= 0x0000ffff;
			data1 |= (PCI_CLASS_BRIDGE_PCI << 16);
			*(volatile unsigned int *)addrp = cpu_to_le32(data1);
			register_pci_controller(&ls2h_pcie_controller1);

			//enable LTSSM of port2
			addrp = (void *)CKSEG1ADDR(LS2H_PCIE_REG_BASE_PORT(2)
						| LS2H_PCIE_PORT_REG_CTR0);
			*(volatile unsigned int *)addrp = cpu_to_le32(0xff204c);
			//modify PCI class of port2
			addrp = (void *)CKSEG1ADDR(LS2H_PCIE_PORT_HEAD_BASE_PORT(2)
						| PCI_CLASS_REVISION);
			data1 = le32_to_cpu(*(volatile unsigned int *)addrp);
			data1 &= 0x0000ffff;
			data1 |= (PCI_CLASS_BRIDGE_PCI << 16);
			*(volatile unsigned int *)addrp = cpu_to_le32(data1);
			register_pci_controller(&ls2h_pcie_controller2);

			//enable LTSSM of port3
			addrp = (void *)CKSEG1ADDR(LS2H_PCIE_REG_BASE_PORT(3)
						| LS2H_PCIE_PORT_REG_CTR0);
				*(volatile unsigned int *)addrp = cpu_to_le32(0xff204c);
			//modify PCI class of port3
			addrp = (void *)CKSEG1ADDR(LS2H_PCIE_PORT_HEAD_BASE_PORT(3)
						| PCI_CLASS_REVISION);
			data1 = le32_to_cpu(*(volatile unsigned int *)addrp);
			data1 &= 0x0000ffff;
			data1 |= (PCI_CLASS_BRIDGE_PCI << 16);
			*(volatile unsigned int *)addrp = cpu_to_le32(data1);
			register_pci_controller(&ls2h_pcie_controller3);
			}
		}
	}

#ifdef CONFIG_LOAD_PCICFG
	pciload(&ls2h_pci_ops_port0);
	pciload(&ls2h_pci_ops_port1);
	pciload(&ls2h_pci_ops_port2);
	pciload(&ls2h_pci_ops_port3);
#endif
	return 0;
}

static int __init disablepci_setup(char *options)
{
	if (!options || !*options)
		return 0;
	if(options[0]=='0')disablepci=0;
	else disablepci=simple_strtoul(options,0,0);
	return 1;
}

__setup("disablepci=", disablepci_setup);
