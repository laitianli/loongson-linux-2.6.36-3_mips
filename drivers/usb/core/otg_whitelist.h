/*
 * drivers/usb/core/otg_whitelist.h
 *
 * Copyright (C) 2004 Texas Instruments
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This OTG Whitelist is the OTG "Targeted Peripheral List".  It should
 * mostly use of USB_DEVICE() or USB_DEVICE_VER() entries..
 *
 * YOU _SHOULD_ CHANGE THIS LIST TO MATCH YOUR PRODUCT AND ITS TESTING!
 */

static struct usb_device_id whitelist_table [] = {

/* hubs are optional in OTG, but very handy ... */
//#define CERT_WITHOUT_HUBS
#if defined(CERT_WITHOUT_HUBS)
{ USB_DEVICE( 0x0000, 0x0000 ), }, /* Root HUB Only*/
#else
{ USB_DEVICE_INFO(USB_CLASS_HUB, 0, 0), },
{ USB_DEVICE_INFO(USB_CLASS_HUB, 0, 1), },
{ USB_DEVICE_INFO(USB_CLASS_HUB, 0, 2), },
#endif

#ifdef	CONFIG_USB_PRINTER		/* ignoring nonstatic linkage! */
/* FIXME actually, printers are NOT supposed to use device classes;
 * they're supposed to use interface classes...
 */
//{ USB_DEVICE_INFO(7, 1, 1) },
//{ USB_DEVICE_INFO(7, 1, 2) },
//{ USB_DEVICE_INFO(7, 1, 3) },
#endif

#ifdef	CONFIG_USB_NET_CDCETHER
/* Linux-USB CDC Ethernet gadget */
//{ USB_DEVICE(0x0525, 0xa4a1), },
/* Linux-USB CDC Ethernet + RNDIS gadget */
//{ USB_DEVICE(0x0525, 0xa4a2), },
#endif

#if	defined(CONFIG_USB_TEST) || defined(CONFIG_USB_TEST_MODULE)
/* gadget zero, for testing */
//{ USB_DEVICE(0x0525, 0xa4a0), },
#endif

{ USB_DEVICE( 0x1a0a, 0x0101 ), }, /* TEST_SE0_NAK */
{ USB_DEVICE( 0x1a0a, 0x0102 ), }, /* Test_J */
{ USB_DEVICE( 0x1a0a, 0x0103 ), }, /* Test_K */
{ USB_DEVICE( 0x1a0a, 0x0104 ), }, /* Test_PACKET */
{ USB_DEVICE( 0x1a0a, 0x0105 ), }, /* Test_FORCE_ENABLE */
{ USB_DEVICE( 0x1a0a, 0x0106 ), }, /* HS_PORT_SUSPEND_RESUME  */
{ USB_DEVICE( 0x1a0a, 0x0107 ), }, /* SINGLE_STEP_GET_DESCRIPTOR setup */
{ USB_DEVICE( 0x1a0a, 0x0108 ), }, /* SINGLE_STEP_GET_DESCRIPTOR execute */
{ USB_DEVICE_VER(0x054c,0x0010,0x0410, 0x0500), },
{ USB_DEVICE( 0x0EA0, 0x2168 ), }, /* Ours Technology Inc. (BUFFALO ClipDrive)*/
{ }	/* Terminating entry */
};

static inline void report_errors(struct usb_device *dev)
{
	dev_info(&dev->dev, "device Vendor:%04x Product:%04x is not supported\n",
                le16_to_cpu(dev->descriptor.idVendor),
                le16_to_cpu(dev->descriptor.idProduct));
        if (USB_CLASS_HUB == dev->descriptor.bDeviceClass){
                dev_printk(KERN_CRIT, &dev->dev, "Unsupported Hub Topology\n");
        } else {        
                dev_printk(KERN_CRIT, &dev->dev, "Attached Device is not Supported\n");
        }
}

static int is_targeted(struct usb_device *dev)
{
	struct usb_device_id	*id = whitelist_table;

	/* possible in developer configs only! */
	if (!dev->bus->otg_port)
		return 1;

	/* HNP test device is _never_ targeted (see OTG spec 6.6.6) */
	if ((le16_to_cpu(dev->descriptor.idVendor) == 0x1a0a) &&
		(le16_to_cpu(dev->descriptor.idProduct) == 0xbadd)) {
                return 0;
	} else if (!enable_whitelist) {
               return 1;
        } else {
#ifdef DEBUG
                dev_dbg(&dev->dev, "device V:%04x P:%04x DC:%04x SC:%04x PR:%04x \n",
                        dev->descriptor.idVendor,
                        dev->descriptor.idProduct,
                        dev->descriptor.bDeviceClass,
                        dev->descriptor.bDeviceSubClass,
                        dev->descriptor.bDeviceProtocol);
#endif
	/* NOTE: can't use usb_match_id() since interface caches
	 * aren't set up yet. this is cut/paste from that code.
	 */
	for (id = whitelist_table; id->match_flags; id++) {
#ifdef DEBUG
			dev_dbg(&dev->dev, 
				"ID: V:%04x P:%04x DC:%04x SC:%04x PR:%04x \n",
				id->idVendor,
				id->idProduct,
				id->bDeviceClass,
				id->bDeviceSubClass,
				id->bDeviceProtocol);
#endif                  
		if ((id->match_flags & USB_DEVICE_ID_MATCH_VENDOR) &&
		    id->idVendor != le16_to_cpu(dev->descriptor.idVendor))
			continue;

		if ((id->match_flags & USB_DEVICE_ID_MATCH_PRODUCT) &&
		    id->idProduct != le16_to_cpu(dev->descriptor.idProduct))
			continue;

		/* No need to test id->bcdDevice_lo != 0, since 0 is never
		   greater than any unsigned number. */
		if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_LO) &&
		    (id->bcdDevice_lo > le16_to_cpu(dev->descriptor.bcdDevice)))
			continue;

		if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_HI) &&
		    (id->bcdDevice_hi < le16_to_cpu(dev->descriptor.bcdDevice)))
			continue;

		if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_CLASS) &&
		    (id->bDeviceClass != dev->descriptor.bDeviceClass))
			continue;

		if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) &&
		    (id->bDeviceSubClass != dev->descriptor.bDeviceSubClass))
			continue;

		if ((id->match_flags & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) &&
		    (id->bDeviceProtocol != dev->descriptor.bDeviceProtocol))
			continue;

		return 1;
	}
	}

	/* add other match criteria here ... */


	/* OTG MESSAGE: report errors here, customize to match your product */
	dev_err(&dev->dev, "device v%04x p%04x is not supported\n",
		le16_to_cpu(dev->descriptor.idVendor),
		le16_to_cpu(dev->descriptor.idProduct));
#ifdef	CONFIG_USB_OTG_WHITELIST
	report_errors(dev);
	return 0;
#else
	if (enable_whitelist) {
		report_errors(dev);
		return 0;
	} else {
	return 1;
	}
#endif
}

