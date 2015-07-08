/*
 * Platform device support for GS232 SoCs.
 *
 * Copyright 2009, Su Wen <suwen@ict.ac.cn>
 *	
 * base on Au1xxx Socs drivers by Matt Porter <mporter@kernel.crashing.org>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/resource.h>
#include <linux/serial_8250.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <linux/delay.h>

#include <ls2h/ls2h.h>
#include <ls2h/ls2h_int.h>
#include <boot_param.h>

/*
 * uart
 */
struct plat_serial8250_port ls2h_uart8250_data[] = {
	[0] = {
		.mapbase	= CKSEG1ADDR(LS2H_UART0_REG_BASE),
		.uartclk	= 125000000,
		.membase	= (void *)CKSEG1ADDR(LS2H_UART0_REG_BASE),
		.irq		= LS2H_UART0_IRQ,
		.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,
		.iotype		= UPIO_MEM,
		.regshift	= 0,
	},
	[1] = {
		.mapbase	= CKSEG1ADDR(LS2H_UART1_REG_BASE),
		.uartclk	= 125000000,
		.membase	= (void *)CKSEG1ADDR(LS2H_UART1_REG_BASE),
		.irq		= LS2H_UART1_IRQ,
		.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,
		.iotype		= UPIO_MEM,
		.regshift	= 0,
	},
	[2] = {
		.mapbase	= CKSEG1ADDR(LS2H_UART2_REG_BASE),
		.uartclk	= 125000000,
		.membase	= (void *)CKSEG1ADDR(LS2H_UART2_REG_BASE),
		.irq		= LS2H_UART2_IRQ,
		.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,
		.iotype		= UPIO_MEM,
		.regshift	= 0,
	},
	[3] = {
		.mapbase	= CKSEG1ADDR(LS2H_UART3_REG_BASE),
		.uartclk	= 125000000,
		.membase	= (void *)CKSEG1ADDR(LS2H_UART3_REG_BASE),
		.irq		= LS2H_UART3_IRQ,
		.flags		= UPF_BOOT_AUTOCONF | UPF_SKIP_TEST,
		.iotype		= UPIO_MEM,
		.regshift	= 0,
	},
	{}
};

static struct platform_device uart8250_device = {
	.name	= "serial8250",
	.id	= PLAT8250_DEV_PLATFORM1,
	.dev	= {
		.platform_data = ls2h_uart8250_data,
	}
};

/*
 * nand 
 */

struct ls2h_nand_platform_data{
	int enable_arbiter;
	struct mtd_partition *parts;
	unsigned int nr_parts;
};

static struct mtd_partition ls2h_nand_partitions[]={
	[0] = {
		.name	= "kernel",
		.offset	= 0,
		.size	= 0x01400000,
	},
	[1] = {
		.name	= "os",
		.offset	= 0x01400000,
		.size	= 0x0,

	},
};

static struct ls2h_nand_platform_data ls2h_nand_parts = {
	.enable_arbiter = 1,
	.parts		= ls2h_nand_partitions,
	.nr_parts	= ARRAY_SIZE(ls2h_nand_partitions),
};

static struct resource ls2h_nand_resources[] = {
	[0] = {
		.start	= 0,
		.end	= 0,
		.flags	= IORESOURCE_DMA,
	},
	[1] = {
		.start	= LS2H_NAND_REG_BASE,
		.end	= LS2H_NAND_REG_BASE + 0x20,
		.flags	= IORESOURCE_MEM,
	},
	[2] = {
		.start	= LS2H_DMA_ORDER_REG,
		.end	= LS2H_DMA_ORDER_REG,
		.flags	= IORESOURCE_MEM,
	},
	[3] = {
		.start	= LS2H_DMA0_IRQ,
		.end	= LS2H_DMA0_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

struct platform_device ls2h_nand_device = {
	.name	= "ls2h-nand",
	.id	= -1,
	.dev	= {
		.platform_data = &ls2h_nand_parts,
	},
	.num_resources	= ARRAY_SIZE(ls2h_nand_resources),
	.resource	= ls2h_nand_resources,
};

/*
 * ohci
 */

static u64 dma_mask = 0xffffffff;

static struct resource ls2h_ohci_resources[] = { 
	[0] = {
		.start	= LS2H_OHCI_REG_BASE,
		.end	= (LS2H_OHCI_REG_BASE + 0x1000 - 1),
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= LS2H_OHCI_IRQ,
		.end	= LS2H_OHCI_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct ls2h_usbh_data ls2h_ohci_platform_data = {
	.ports=6,
};

static struct platform_device ls2h_ohci_device = {
	.name	= "ls2h-ohci",
	.id	= 0,
	.dev	= {
		.platform_data	= &ls2h_ohci_platform_data,
		.dma_mask	= &dma_mask,
	},
	.num_resources	= ARRAY_SIZE(ls2h_ohci_resources),
	.resource	= ls2h_ohci_resources,
};

/*
 * ehci
 */

static struct resource ls2h_ehci_resources[] = { 
	[0] = {
		.start	= LS2H_EHCI_REG_BASE,
		.end	= (LS2H_EHCI_REG_BASE + 0x6b),
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= LS2H_EHCI_IRQ,
		.end	= LS2H_EHCI_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct ls2h_usbh_data ls2h_ehci_platform_data = {
	.ports = 4,
};

static struct platform_device ls2h_ehci_device = {
	.name	= "ls2h-ehci",
	.id	= -1,
	.dev	= {
		.platform_data	= &ls2h_ehci_platform_data,
		.dma_mask	= &dma_mask,
	},
	.num_resources	= ARRAY_SIZE(ls2h_ehci_resources),
	.resource	= ls2h_ehci_resources,
};

/*
 * gmac
 */

static struct resource ls2h_gmac0_resources[] = { 
	[0] = {
		.start	= LS2H_GMAC0_REG_BASE,
		.end	= (LS2H_GMAC0_REG_BASE + 0x6b),
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= LS2H_GMAC0_IRQ,
		.end	= LS2H_GMAC0_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_gmac0_device = {
	.name	= "ls2h-gmac",
	.id	= 0,
	.dev	= {
		.dma_mask = &dma_mask,
	},
	.num_resources	= ARRAY_SIZE(ls2h_gmac0_resources),
	.resource	= ls2h_gmac0_resources,
};


static struct resource ls2h_gmac1_resources[] = { 
	[0] = {
		.start	= LS2H_GMAC1_REG_BASE,
		.end	= (LS2H_GMAC1_REG_BASE + 0x6b),
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= LS2H_GMAC1_IRQ,
		.end	= LS2H_GMAC1_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_gmac1_device = {
	.name	= "ls2h-gmac",
	.id	= 1,
	.dev	= {
		.dma_mask = &dma_mask,
	},
	.num_resources	= ARRAY_SIZE(ls2h_gmac1_resources),
	.resource	= ls2h_gmac1_resources,
};

/*
 * ahci
 */

static struct resource ls2h_ahci_resources[] = { 
	[0] = {
		.start	= LS2H_SATA_REG_BASE,
		.end	= LS2H_SATA_REG_BASE+0x1ff,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= LS2H_SATA_IRQ,
		.end	= LS2H_SATA_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_ahci_device = {
	.name	= "ahci",
	.id	= -1,
	.dev	= {
		.dma_mask	= &dma_mask,
	},
	.num_resources	= ARRAY_SIZE(ls2h_ahci_resources),
	.resource	= ls2h_ahci_resources,
};

/**
 * rtc
 */

static struct resource ls2h_rtc_resources[] = { 
       [0] = {
               .start  = LS2H_RTC_REG_BASE,
               .end    = (LS2H_RTC_REG_BASE + 0xff),
               .flags  = IORESOURCE_MEM,
       },
       [1] = {
               .start  = LS2H_RTC_INT0_IRQ,
               .end    = LS2H_TOY_TICK_IRQ,
               .flags  = IORESOURCE_IRQ,
       },
};

static struct platform_device ls2h_rtc_device = {
       .name   = "ls2h-rtc",
       .id     = 0,
       .num_resources  = ARRAY_SIZE(ls2h_rtc_resources),
       .resource       = ls2h_rtc_resources,
};

/*
 * dc
 */

static struct resource ls2h_dc_resources[] = { 
	[0] = {
		.start	= LS2H_DC_REG_BASE,
		.end	= LS2H_DC_REG_BASE + 0x2000,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= LS2H_DC_IRQ,
		.end	= LS2H_DC_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_dc_device = {
	.name	= "ls2h-fb",
	.id	= 0,
	.num_resources	= ARRAY_SIZE(ls2h_dc_resources),
	.resource	= ls2h_dc_resources,
};

/*
 * HD Audio
 */

static struct resource ls2h_audio_resources[] = {
	[0] = {
		.start = LS2H_HDA_REG_BASE,
		.end   = LS2H_HDA_REG_BASE + 0x17f,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start = LS2H_HDA_IRQ,
		.end   = LS2H_HDA_IRQ,
		.flags = IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_audio_device = {
	.name           = "ls2h-audio",
	.id             = 0,
	.num_resources  = ARRAY_SIZE(ls2h_audio_resources),
	.resource       = ls2h_audio_resources,
};

/*
 * I2C
 */

static struct resource ls2h_i2c0_resources[] = {
	[0] = {
		.start = LS2H_I2C0_REG_BASE,
		.end   = LS2H_I2C0_REG_BASE + 0x8,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start = LS2H_I2C0_IRQ,
		.end   = LS2H_I2C0_IRQ,
		.flags = IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_i2c0_device = {
	.name           = "ls2h-i2c",
	.id             = 0,
	.num_resources  = ARRAY_SIZE(ls2h_i2c0_resources),
	.resource       = ls2h_i2c0_resources,
};

static struct resource ls2h_i2c1_resources[] = {
	[0] = {
		.start = LS2H_I2C1_REG_BASE,
		.end   = LS2H_I2C1_REG_BASE + 0x8,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start = LS2H_I2C1_IRQ,
		.end   = LS2H_I2C1_IRQ,
		.flags = IORESOURCE_IRQ,
	},
};

static struct platform_device ls2h_i2c1_device = {
	.name           = "ls2h-i2c",
	.id             = 1,
	.num_resources  = ARRAY_SIZE(ls2h_i2c1_resources),
	.resource       = ls2h_i2c1_resources,
};

static struct platform_device *ls2h_platform_devices[] __initdata = {
	&uart8250_device,
	&ls2h_i2c0_device,
	&ls2h_i2c1_device,
	&ls2h_nand_device,
	&ls2h_ohci_device,
	&ls2h_ehci_device,
	&ls2h_gmac0_device,
	&ls2h_gmac1_device,
	&ls2h_ahci_device,
	&ls2h_dc_device, 
	&ls2h_rtc_device,
	&ls2h_audio_device,
};

static int ls2h_platform_init(void)
{
	unsigned int tmp;

	/*
	 * chip_config0 : 0x1fd00200
	 *
	 * bit[26]:	usb reset,		0: reset        1: disable reset
	 * bit[14]:	host/otg select,	0: host         1: otg
	 * bit[4]:	ac97/hda select,	0: ac97		1: hda
	 *
	 */
	tmp = ls2h_readw(LS2H_CHIP_CFG0_REG);
	tmp |= (1<<4) | (1<<26);
	ls2h_writew(tmp, LS2H_CHIP_CFG0_REG);

	platform_set_drvdata(&ls2h_gmac0_device, (void *)1);
	platform_set_drvdata(&ls2h_gmac1_device, (void *)1);
	platform_set_drvdata(&ls2h_dc_device, (void *)1);

	return platform_add_devices(ls2h_platform_devices, 
			ARRAY_SIZE(ls2h_platform_devices));
}

static int __init platform_dev_init(void)
{
	if(board_type == LS2H)
		return ls2h_platform_init();
	else
		return 0;
}

device_initcall(platform_dev_init);
