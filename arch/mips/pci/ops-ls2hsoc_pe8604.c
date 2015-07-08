/*
 * ops-ls2hsoc.c
 *
 * Copyright (C) 2004 ICT CAS
 * Author: Li xiaoyu, ICT CAS
 *   lixy@ict.ac.cn
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

#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>

#define PCI_ACCESS_READ  0
#define PCI_ACCESS_WRITE 1

#define PCI_BASE_ADDRESS_6	0x28	/* 32 bits */
#define PCI_BASE_ADDRESS_7	0x2c	/* 32 bits */
#define PCI_BASE_ADDRESS_8	0x30	/* 32 bits */


#ifndef CONFIG_LS2H_PCIE
static inline void bflush(void)
{
	/* flush Bonito register writes */
	(void)LS2H_PCIMAP_CFG;
}
#endif

#ifndef CONFIG_LS2H_PCIE
static int ls2h_pci_config_access(unsigned char access_type,
				  struct pci_bus *bus, unsigned int devfn,
				  int where, u32 * data)
{

	unsigned char busnum = bus->number;

	u_int32_t addr, type;
	void *addrp;
	int device = devfn >> 3;
	int function = devfn & 0x7;
	int reg = where & ~3;

	if (busnum == 0) {
		/* Type 0 configuration on onboard PCI bus */
		if (device > 20 || function > 7) {
			*data = -1;	/* device out of range */
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		addr = (1 << (device + 11)) | (function << 8) | reg;
		type = 0;
	} else {
		/* Type 1 configuration on offboard PCI bus */
		if (busnum > 255 || device > 31 || function > 7) {
			*data = -1;	/* device out of range */
			return PCIBIOS_DEVICE_NOT_FOUND;
		}
		addr = (busnum << 16) | (device << 11) | (function << 8) | reg;
		type = 0x10000;
	}

	/* clear aborts */
//      LS2H_PCICMD |= LS2H_PCICMD_MABORT | LS2H_PCICMD_MTABORT;

	LS2H_PCIMAP_CFG = (addr >> 16) | type;
	bflush();

	addrp = (void *)CKSEG1ADDR(LS2H_PCICFG_BASE | (addr & 0xffff));
	if (access_type == PCI_ACCESS_WRITE) {
		*(volatile unsigned int *)addrp = cpu_to_le32(*data);
	} else {
		*data = le32_to_cpu(*(volatile unsigned int *)addrp);
	}

#if 0
	if (LS2H_PCICMD & (LS2H_PCICMD_MABORT | LS2H_PCICMD_MTABORT)) {
		LS2H_PCICMD |= LS2H_PCICMD_MABORT | LS2H_PCICMD_MTABORT;
		*data = -1;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}
#endif

	return PCIBIOS_SUCCESSFUL;
}

#else
static u32 ls2h_pcie_bar_translate(unsigned char access_type, u32 bar_in,
				   unsigned char portnum)
{

	static unsigned char tag_mem = 0, tag_io = 0;

	if (portnum > LS2H_PCIE_MAX_PORTNUM)
		return bar_in;

	if ((access_type == PCI_ACCESS_WRITE) && LIE_IN_WINDOW(bar_in,
							       LS2H_PCIE_MEM0_DOWN_BASE,
							       LS2H_PCIE_MEM0_DOWN_MASK))
		return MAP_2_WINDOW(bar_in, LS2H_PCIE_MEM0_UP_BASE,
				    LS2H_PCIE_MEM0_UP_MASK);
	//it's a little tricky here

	if ((access_type == PCI_ACCESS_READ) && LIE_IN_WINDOW(bar_in,
							      LS2H_PCIE_MEM0_UP_BASE,
							      LS2H_PCIE_MEM0_UP_MASK))
	{
		if (tag_mem)
			return MAP_2_WINDOW(bar_in,
					    LS2H_PCIE_MEM0_BASE_PORT(portnum),
					    LS2H_PCIE_MEM0_UP_MASK);
		else {
			tag_mem = 1;
			return bar_in;
		}
	}

	if ((access_type == PCI_ACCESS_WRITE) && LIE_IN_WINDOW(bar_in,
							       LS2H_PCIE_IO_DOWN_BASE,
							       LS2H_PCIE_IO_DOWN_MASK))
		return MAP_2_WINDOW(bar_in, LS2H_PCIE_IO_UP_BASE,
				    LS2H_PCIE_IO_UP_MASK);

	if ((access_type == PCI_ACCESS_READ) && LIE_IN_WINDOW(bar_in,
							      LS2H_PCIE_IO_UP_BASE,
							      LS2H_PCIE_IO_UP_MASK)
	    && (bar_in & PCI_BASE_ADDRESS_SPACE_IO)) {
		if (tag_io)
			return MAP_2_WINDOW(bar_in,
					    LS2H_PCIE_IO_BASE_PORT(portnum),
					    LS2H_PCIE_IO_UP_MASK);
		else {
			tag_io = 1;
			return bar_in;
		}
	}

	return bar_in;
}

static u32 ls2h_pcie_bridge_bar_translate(unsigned char access_type, u32 bar_in,
				   unsigned char portnum, int reg)
{
	if (portnum > LS2H_PCIE_MAX_PORTNUM)
		return bar_in;

#if 1
	//1. deal with write
	  switch (reg){
		case PCI_BASE_ADDRESS_4:
		case PCI_BASE_ADDRESS_5:
		case PCI_BASE_ADDRESS_8:
		  if (access_type == PCI_ACCESS_WRITE)
			bar_in -= 0x02000200 * portnum;	
		  if (access_type == PCI_ACCESS_READ)
			bar_in += 0x02000200 * portnum;	
		  //break;
		case PCI_BASE_ADDRESS_6:
		case PCI_BASE_ADDRESS_7:
		default:
		  return bar_in;
	}
#endif

	return bar_in;
}

static int ls2h_pci_config_access(unsigned char access_type,
				  struct pci_bus *bus, unsigned int devfn,
				  int where, u32 * data, unsigned char portnum)
{

	unsigned char busnum = bus->number;

	u_int32_t addr, type;
	u_int32_t addr_i, cfg_addr, reg_data;
	u32 datarp;
	void *addrp;
	unsigned long testp;
	int device = devfn >> 3;
	int function = devfn & 0x7;
	int reg = where & ~3;
	unsigned char need_bar_translate = 0;
	unsigned char bridge_need_bar_translate = 0;

	if (portnum > LS2H_PCIE_MAX_PORTNUM)
		return PCIBIOS_DEVICE_NOT_FOUND;

	//printk("ls2h_pci_config_access: acctype %d, devfn %d, portnum %d", access_type, devfn, portnum);


	if (!bus->parent) {
		/* in-chip virtual-bus has no parent,
		   so access is routed to PORT_HEAD */
		if (device > 0 || function > 0) {
			*data = -1;	/* only one Controller lay on a virtual-bus */
			//printk("1. PCIBIOS_DEVICE_NOT_FOUND: busnum = %d, device = %d, function = %d\n", busnum, device, function);
			return PCIBIOS_DEVICE_NOT_FOUND;
		} else {
			//printk
			//("X. PCIBIOS_DEVICE_FOUND: busnum = %d, device = %d, function = %d\n",
			//busnum, device, function);
			addr = LS2H_PCIE_PORT_HEAD_BASE_PORT(portnum) | reg;
			if (reg == PCI_BASE_ADDRESS_0)
				/* the default value of PCI_BASE_ADDRESS_0 of
				   PORT_HEAD is wrong, use PCI_BASE_ADDESS_1 instead */
				addr += 4;
		}
	}

	else {
		/* offboard PCIE-bus has parent,
		   so access is routed to DEV_HEAD */

		/* check if LTSSM of controller link-up */
		addr_i = LS2H_PCIE_REG_BASE_PORT(portnum)
		    | LS2H_PCIE_PORT_REG_STAT1;
		addrp = (void *)CKSEG1ADDR(addr_i);
		reg_data = le32_to_cpu(*(volatile unsigned int *)addrp);
		if (busnum > 255 || device > 31 || function > 7
		    || !(reg_data & LS2H_PCIE_REG_STAT1_BIT_LINKUP)) {
			*data = -1;	/* link is not up at all  */
			//printk("2. PCIBIOS_DEVICE_NOT_FOUND: busnum = %d\n", busnum);
			return PCIBIOS_DEVICE_NOT_FOUND;
		}

		if (!bus->parent->parent) {
			/* the bus is child of virtual-bus(pcie slot),
			   so use Type 0 access for device on it */
			if (device > 0 || busnum == 3 && ((reg >= PCI_BASE_ADDRESS_0 && 
				reg <= PCI_BASE_ADDRESS_1))) { // skip bar of pci bridge
				//printk("Skip busnum:%d, device:%d, fun:%d\n",
				 //      busnum, device, function);
				*data = -1;	/* only one device on PCIE slot */
				return PCIBIOS_DEVICE_NOT_FOUND;
			}
			//if ( busnum == 3 && reg >= PCI_BASE_ADDRESS_4 && reg <= PCI_BASE_ADDRESS_5)
			//if ( busnum == 3 && reg == PCI_BASE_ADDRESS_4 )
			type = 0;
		} else {
			/* the bus is emitted from offboard-bridge,
			   so use Type 1 access for device on it */
  
			//printk("Config access: busnum:%d, device:%d, fun:%d, tyep:%d\n",
			//	       busnum, device, function, access_type);
#if 1
			switch (busnum) {
			  case 4:
				//if ( device == 1 || device == 4 || device == 5 && !(reg >= PCI_BASE_ADDRESS_0 && reg <= PCI_BASE_ADDRESS_1))
				if ( device == 1 || device == 4 || device == 5)
				  if (reg ==  PCI_BASE_ADDRESS_0  ||  reg ==  PCI_BASE_ADDRESS_1) {
					*data = -1;	/* only one device on PCIE slot */
					return PCIBIOS_DEVICE_NOT_FOUND;
				  } else
					  type = 1;
				else {
				 // printk("Skip busnum:%d, device:%d, fun:%d\n",
				  //     busnum, device, function);
				  *data = -1;	/* only one device on PCIE slot */
				  return PCIBIOS_DEVICE_NOT_FOUND;
				}
				break;
			  case 6:
			  case 7:
			  case 5:
				if (device > 0) {
				  printk("Skip busnum:%d, device:%d, fun:%d\n",
				       busnum, device, function);
				  *data = -1;	/* only one device on PCIE slot */
				  return PCIBIOS_DEVICE_NOT_FOUND;
				} 
				type = 1;
				break;
			  default:
				  return PCIBIOS_DEVICE_NOT_FOUND;
		  }
#else
		  if (busnum >= 4 && busnum <= 7)
				  return PCIBIOS_DEVICE_NOT_FOUND;
#endif
	  }

		/* write busnum/devnum/funcnum/type into PCIE_REG_BASE +0x24 */
		addr_i = LS2H_PCIE_REG_BASE_PORT(portnum)
		    | LS2H_PCIE_PORT_REG_CFGADDR;
		cfg_addr =
		    (busnum << 16) | (device << 11) | (function << 8) | type;
		addrp = (void *)CKSEG1ADDR(addr_i);
		*(volatile unsigned int *)addrp = cpu_to_le32(cfg_addr);	//config access: step 1

		/* access mapping memory instead of direct configuration access */
		addr = LS2H_PCIE_DEV_HEAD_BASE_PORT(portnum) | reg;	//config access: step 2.1,(0x18116000 + (portnum << 22))

#if 0
		if (reg >= PCI_BASE_ADDRESS_0 && reg <= PCI_BASE_ADDRESS_5)
#else
		if( busnum <= 4 && busnum >=3 && reg >= PCI_BASE_ADDRESS_4 && reg <= PCI_BASE_ADDRESS_8 )
			bridge_need_bar_translate = 1;
		else
		  if (reg >= PCI_BASE_ADDRESS_0 && reg <= PCI_BASE_ADDRESS_5 )
			need_bar_translate = 1;
#endif
			/* Base Address Register need to be translated */
	}

	addrp = (void *)CKSEG1ADDR(addr);	// config access
	if (access_type == PCI_ACCESS_WRITE) {
		if (need_bar_translate) {
			datarp =
			    ls2h_pcie_bar_translate(PCI_ACCESS_WRITE, *data,
						    portnum);
			//printk("%x:%x:%x:%x trans write: before %08x, after %08x\n",busnum,device,function,reg, *data, datarp);
		} else if (bridge_need_bar_translate) {
			datarp =
			    ls2h_pcie_bridge_bar_translate(PCI_ACCESS_WRITE, *data,
						    portnum, reg);
			//printk("%x:%x:%x:%x btrans write: before %08x, after %08x\n",busnum,device,function,reg, *data, datarp);

		  } else
			datarp = *data;

		*(volatile unsigned int *)addrp = cpu_to_le32(datarp);
	} else {
		datarp = le32_to_cpu(*(volatile unsigned int *)addrp);	// config access step 2.2
		if (need_bar_translate) {
			*data =
			    ls2h_pcie_bar_translate(PCI_ACCESS_READ, datarp,
						    portnum);
			//printk("%x:%x:%x:%x trans read: before %08x, after %08x\n",busnum,device,function,reg, datarp, *data);
		} else if (bridge_need_bar_translate) {
			*data =
			    ls2h_pcie_bridge_bar_translate(PCI_ACCESS_READ, datarp,
						    portnum, reg);
			//printk("%x:%x:%x:%x btrans read: before %08x, after %08x\n",busnum,device,function,reg, datarp, *data);
		  } else
			*data = datarp;
	}

	return PCIBIOS_SUCCESSFUL;
}
#endif

#ifndef CONFIG_LS2H_PCIE
static int ls2h_pci_pcibios_read(struct pci_bus *bus, unsigned int devfn,
				 int where, int size, u32 * val)
{
	u32 data = 0;

	if (ls2h_pci_config_access(PCI_ACCESS_READ, bus, devfn, where, &data))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (size == 1)
		*val = (data >> ((where & 3) << 3)) & 0xff;
	else if (size == 2)
		*val = (data >> ((where & 3) << 3)) & 0xffff;
	else
		*val = data;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_write(struct pci_bus *bus, unsigned int devfn,
				  int where, int size, u32 val)
{
	u32 data = 0;

	if (size == 4)
		data = val;
	else {
		if (ls2h_pci_config_access
		    (PCI_ACCESS_READ, bus, devfn, where, &data))
			return PCIBIOS_DEVICE_NOT_FOUND;

		if (size == 1)
			data = (data & ~(0xff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
		else if (size == 2)
			data = (data & ~(0xffff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
	}

	if (ls2h_pci_config_access(PCI_ACCESS_WRITE, bus, devfn, where, &data))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return PCIBIOS_SUCCESSFUL;
}

#else
static int ls2h_pci_pcibios_read_port0(struct pci_bus *bus, unsigned int devfn,
				       int where, int size, u32 * val)
{
	u32 data = 0;

	if (ls2h_pci_config_access
	    (PCI_ACCESS_READ, bus, devfn, where, &data, LS2H_PCIE_PORT0))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (size == 1)
		*val = (data >> ((where & 3) << 3)) & 0xff;
	else if (size == 2)
		*val = (data >> ((where & 3) << 3)) & 0xffff;
	else
		*val = data;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_write_port0(struct pci_bus *bus, unsigned int devfn,
					int where, int size, u32 val)
{
	u32 data = 0;

	if (size == 4)
		data = val;
	else {
		if (ls2h_pci_config_access
		    (PCI_ACCESS_READ, bus, devfn, where, &data,
		     LS2H_PCIE_PORT0))
			return PCIBIOS_DEVICE_NOT_FOUND;

		if (size == 1)
			data = (data & ~(0xff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
		else if (size == 2)
			data = (data & ~(0xffff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
	}

	if (ls2h_pci_config_access
	    (PCI_ACCESS_WRITE, bus, devfn, where, &data, LS2H_PCIE_PORT0))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_read_port1(struct pci_bus *bus, unsigned int devfn,
				       int where, int size, u32 * val)
{
	u32 data = 0;

	if (ls2h_pci_config_access
	    (PCI_ACCESS_READ, bus, devfn, where, &data, LS2H_PCIE_PORT1))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (size == 1)
		*val = (data >> ((where & 3) << 3)) & 0xff;
	else if (size == 2)
		*val = (data >> ((where & 3) << 3)) & 0xffff;
	else
		*val = data;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_write_port1(struct pci_bus *bus, unsigned int devfn,
					int where, int size, u32 val)
{
	u32 data = 0;

	if (size == 4)
		data = val;
	else {
		if (ls2h_pci_config_access
		    (PCI_ACCESS_READ, bus, devfn, where, &data,
		     LS2H_PCIE_PORT1))
			return PCIBIOS_DEVICE_NOT_FOUND;

		if (size == 1)
			data = (data & ~(0xff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
		else if (size == 2)
			data = (data & ~(0xffff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
	}

	if (ls2h_pci_config_access
	    (PCI_ACCESS_WRITE, bus, devfn, where, &data, LS2H_PCIE_PORT1))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_read_port2(struct pci_bus *bus, unsigned int devfn,
				       int where, int size, u32 * val)
{
	u32 data = 0;

	if (ls2h_pci_config_access
	    (PCI_ACCESS_READ, bus, devfn, where, &data, LS2H_PCIE_PORT2))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (size == 1)
		*val = (data >> ((where & 3) << 3)) & 0xff;
	else if (size == 2)
		*val = (data >> ((where & 3) << 3)) & 0xffff;
	else
		*val = data;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_write_port2(struct pci_bus *bus, unsigned int devfn,
					int where, int size, u32 val)
{
	u32 data = 0;

	if (size == 4)
		data = val;
	else {
		if (ls2h_pci_config_access
		    (PCI_ACCESS_READ, bus, devfn, where, &data,
		     LS2H_PCIE_PORT2))
			return PCIBIOS_DEVICE_NOT_FOUND;

		if (size == 1)
			data = (data & ~(0xff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
		else if (size == 2)
			data = (data & ~(0xffff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
	}

	if (ls2h_pci_config_access
	    (PCI_ACCESS_WRITE, bus, devfn, where, &data, LS2H_PCIE_PORT2))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_read_port3(struct pci_bus *bus, unsigned int devfn,
				       int where, int size, u32 * val)
{
	u32 data = 0;

	if (ls2h_pci_config_access
	    (PCI_ACCESS_READ, bus, devfn, where, &data, LS2H_PCIE_PORT3))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (size == 1)
		*val = (data >> ((where & 3) << 3)) & 0xff;
	else if (size == 2)
		*val = (data >> ((where & 3) << 3)) & 0xffff;
	else
		*val = data;

	return PCIBIOS_SUCCESSFUL;
}

static int ls2h_pci_pcibios_write_port3(struct pci_bus *bus, unsigned int devfn,
					int where, int size, u32 val)
{
	u32 data = 0;

	if (size == 4)
		data = val;
	else {
		if (ls2h_pci_config_access
		    (PCI_ACCESS_READ, bus, devfn, where, &data,
		     LS2H_PCIE_PORT3))
			return PCIBIOS_DEVICE_NOT_FOUND;

		if (size == 1)
			data = (data & ~(0xff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
		else if (size == 2)
			data = (data & ~(0xffff << ((where & 3) << 3))) |
			    (val << ((where & 3) << 3));
	}

	if (ls2h_pci_config_access
	    (PCI_ACCESS_WRITE, bus, devfn, where, &data, LS2H_PCIE_PORT3))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return PCIBIOS_SUCCESSFUL;
}
#endif

#ifndef CONFIG_LS2H_PCIE
struct pci_ops ls2h_pci_pci_ops = {
	.read = ls2h_pci_pcibios_read,
	.write = ls2h_pci_pcibios_write
};

#else
struct pci_ops ls2h_pci_pci_ops_port0 = {
	.read = ls2h_pci_pcibios_read_port0,
	.write = ls2h_pci_pcibios_write_port0
};

struct pci_ops ls2h_pci_pci_ops_port1 = {
	.read = ls2h_pci_pcibios_read_port1,
	.write = ls2h_pci_pcibios_write_port1
};

struct pci_ops ls2h_pci_pci_ops_port2 = {
	.read = ls2h_pci_pcibios_read_port2,
	.write = ls2h_pci_pcibios_write_port2
};

struct pci_ops ls2h_pci_pci_ops_port3 = {
	.read = ls2h_pci_pcibios_read_port3,
	.write = ls2h_pci_pcibios_write_port3
};
#endif
