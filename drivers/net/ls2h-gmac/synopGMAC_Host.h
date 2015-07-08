#ifndef SYNOP_GMAC_HOST_H
#define SYNOP_GMAC_HOST_H

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/mii.h>

#include "synopGMAC_plat.h"
#include "synopGMAC_pci_bus_interface.h"
#include "synopGMAC_Dev.h"

#ifdef CONFIG_LS2H_SOC
#ifndef ENH_DESC
#define ENH_DESC
#endif
#endif
typedef struct synopGMACAdapterStruct {

	/*Device Dependent Data structur*/
	synopGMACdevice *synopGMACdev;
	/*Os/Platform Dependent Data Structures*/
	struct device *dev;
	struct platform_device *pdev;
	struct net_device *synopGMACnetdev;
	struct net_device_stats synopGMACNetStats;
	struct mii_if_info mii;
	u32 synopGMACPciState[16];
	u8 *synopGMACMappedAddr;
	u32 synopGMACMappedAddrSize;
	int irq;
	long i2c_bus_id;

	spinlock_t lock;	/* spin lock flag */
	spinlock_t rx_lock;	/* spin lock flag */

} synopGMACPciNetworkAdapter;

#endif
