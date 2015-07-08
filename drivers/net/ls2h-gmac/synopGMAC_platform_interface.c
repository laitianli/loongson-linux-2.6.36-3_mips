#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include "synopGMAC_Host.h"
#include "synopGMAC_network_interface.h"

static int init_one_platform(struct platform_device *pdev)
{
	synopGMACPciNetworkAdapter *synopGMACadapter;
	u8 *synopGMACMappedAddr;
	u32 synopGMACMappedAddrSize;
	u32 irq;
	struct resource *res;

	irq = platform_get_irq(pdev, 0);
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	synopGMACMappedAddrSize = res->end - res->start + 1;
	synopGMACMappedAddr = ioremap_nocache(res->start,
			synopGMACMappedAddrSize);
	TR0("init_one_platform %p\n", synopGMACMappedAddr);

	if ((synopGMACadapter = synopGMAC_init_network_interface(pdev,
					synopGMACMappedAddr,
				       	synopGMACMappedAddrSize, irq))) {
		platform_set_drvdata(pdev, synopGMACadapter);
	}

	spin_lock_init (&synopGMACadapter ->lock);
	spin_lock_init (&synopGMACadapter ->rx_lock);

	return 0;
}

static int remove_one_platform(struct platform_device *pdev)
{
	void *drvdata;
	synopGMACPciNetworkAdapter *adapter = platform_get_drvdata(pdev);
	struct net_device *netdev = adapter->synopGMACnetdev;

	drvdata = (void *)adapter->i2c_bus_id;
	platform_set_drvdata(pdev, drvdata);
	/* Do the reverse of what probe does */
	if (adapter->synopGMACMappedAddr) {
		TR0("Releaseing synopGMACMappedAddr 0x%p whose size is %d\n",
		    adapter->synopGMACMappedAddr,
		    adapter->synopGMACMappedAddrSize);

		/*release the memory region which we locked using request_mem_region */
		release_mem_region((resource_size_t) adapter->
				   synopGMACMappedAddr,
				   adapter->synopGMACMappedAddrSize);
	}
	TR0("Unmapping synopGMACMappedAddr =0x%p\n",
	    adapter->synopGMACMappedAddr);
	iounmap(adapter->synopGMACMappedAddr);
	if (netdev) {
		unregister_netdev(netdev);
		free_netdev(netdev);
	}

	return 0;
}

static struct platform_driver ls2h_gmac_driver = {
	.probe = init_one_platform,
	.remove = remove_one_platform,
	.driver = {
		   .name = "ls2h-gmac",
		   .owner = THIS_MODULE,
		   },
};

static int __init ls2h_gmac_init(void)
{
	platform_driver_register(&ls2h_gmac_driver);
	return 0;
}

module_init(ls2h_gmac_init);

static void __exit ls2h_gmac_exit(void)
{
	platform_driver_unregister(&ls2h_gmac_driver);
}

module_exit(ls2h_gmac_exit);
