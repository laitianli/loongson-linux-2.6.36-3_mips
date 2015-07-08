/**
 * This module can probe temperature for Loongson family CPU. Based timer
 * struct, if temperature over than POWEOFF_TEMP, the system will be halt.
 * If over than WARING_TEMP, the system will warn user.
 *
 * This module compatibled 3A and 3B.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <loongson.h>
#include <boot_param.h>
#include <asm/reboot.h>
#include "temperature.h"

MODULE_LICENSE("GPL");

#define CPU0_SENSOR_BASE		0x900000001fe00190
#define CPU1_SENSOR_BASE		0x900010001fe00190
#define CPU2_SENSOR_BASE		0x900020001fe00190
#define CPU3_SENSOR_BASE		0x900030001fe00190
#define CPU_TEMP_SENSOR0		0xc
#define CPU_TEMP_SENSOR1		0xd
#define DEVNAME				"temphandler"
//#define WARNING_TEMP			70
//#define POWEROFF_TEMP			85

static struct timer_list timer_temp;
static int probe_temp(struct platform_device *);
static int remove_temp(struct platform_device *);
extern enum loongson_cpu_type cputype;

#if PROC_PRINT
struct temperature cpu_temp;
EXPORT_SYMBOL(cpu_temp);
#endif

/**
 * temp_resource struct description cpu sensor's resource.
 * .start: sensor0
 * .end: sensor1
 *
 * 0: 3A desktop
 * 1: 3A server and 3B desktop
 * 2: 3B server and KD90
 */
struct resource temp_resource[] = {
	[0] = {
		.start	= CPU0_SENSOR_BASE + CPU_TEMP_SENSOR0,
		.end	= CPU0_SENSOR_BASE + CPU_TEMP_SENSOR1,
		.name	= DEVNAME,
		.flags	= IORESOURCE_MEM,
	},

	[1] = {
		.start	= CPU1_SENSOR_BASE + CPU_TEMP_SENSOR0,
		.end	= CPU1_SENSOR_BASE + CPU_TEMP_SENSOR1,
		.name	= DEVNAME,
		.flags	= IORESOURCE_MEM,
	},

	[2] = {
		.start	= CPU2_SENSOR_BASE + CPU_TEMP_SENSOR0,
		.end	= CPU2_SENSOR_BASE + CPU_TEMP_SENSOR1,
		.name	= DEVNAME,
		.flags	= IORESOURCE_MEM,
	},

	[3] = {
		.start	= CPU3_SENSOR_BASE + CPU_TEMP_SENSOR0,
		.end	= CPU3_SENSOR_BASE + CPU_TEMP_SENSOR1,
		.name	= DEVNAME,
		.flags	= IORESOURCE_MEM,
	},
};

static struct platform_device temp_device = {
	.name = DEVNAME,
	.id = -1,
	.num_resources = ARRAY_SIZE(temp_resource),
	.resource = temp_resource,
};

struct platform_driver temp_driver = {
	.probe	= probe_temp,
	.remove	= remove_temp,
	.driver = {
		.name	= DEVNAME,
		.owner	= THIS_MODULE,
	}
};

/**
 * Temperature handler.
 * @int cpu_num: CPU number.
 * Read sensor1, because the sensor0
 * can't read out right value.
 *
 * If open MODULE_ACTION, the halt and
 * warning value will be activation.
 *
 * Warning temperature: 70
 * Poweroff temerature: 85
 */
static void temp_handler(int cpu_num)
{
	unsigned char temp[4];
	unsigned char WARNING_TEMP = 70;
	unsigned char POWEROFF_TEMP = 85;

	if ((read_c0_prid() & 0xf) == (PRID_IMP_LOONGSON3B1500 & 0xf)) {
		WARNING_TEMP = 255;
		POWEROFF_TEMP = 255;
	}

	if (cpu_num == 1) {
		temp[0] = *((volatile unsigned char *)temp_device.resource[0].end);
		if (temp[0] >= WARNING_TEMP)
			printk(KERN_INFO "Warning!! High CPU temperature! %d C\n", temp[0]);
#if MODULE_ACTION
		if (temp[0] >= POWEROFF_TEMP)
			goto poweroff;
#endif
	} else if (cpu_num == 2) {
		temp[0] = *((volatile unsigned char *)temp_device.resource[0].end);
		temp[1] = *((volatile unsigned char *)temp_device.resource[1].end);
		if (temp[0] >= WARNING_TEMP || temp[1] >= WARNING_TEMP)
			printk(KERN_INFO "Warning!! High CPU temperature! "
					"CPU0 %d C   CPU1 %d C\n", temp[0], temp[1]);
#if MODULE_ACTION
		if (temp[0] >= POWEROFF_TEMP || temp[1] >= POWEROFF_TEMP)
			goto poweroff;
#endif
	} else if (cpu_num == 4) {
		temp[0] = *((volatile unsigned char *)temp_device.resource[0].end);
		temp[1] = *((volatile unsigned char *)temp_device.resource[1].end);
		temp[2] = *((volatile unsigned char *)temp_device.resource[2].end);
		temp[3] = *((volatile unsigned char *)temp_device.resource[3].end);
		if (temp[0] >= WARNING_TEMP || temp[1] >= WARNING_TEMP ||
			 temp[2] >= WARNING_TEMP || temp[3] >= WARNING_TEMP)
			printk(KERN_INFO "Warning!! High CPU temperature! "
					"CPU0 %d C  CPU1 %d C  CPU2 %d C  CPU3 %d C\n",
					temp[0], temp[1], temp[2], temp[3]);
#if MODULE_ACTION
		if (temp[0] >= POWEROFF_TEMP || temp[1] >= POWEROFF_TEMP ||
			 temp[2] >= POWEROFF_TEMP || temp[3] >= POWEROFF_TEMP)
			goto poweroff;
#endif
	}
#if PROC_PRINT
	if (cpu_num == 1) {
		cpu_temp.cpu_num = 1;
		cpu_temp.temp[0] = *((volatile unsigned char *)temp_device.resource[0].end);
	} else if (cpu_num == 2) {
		cpu_temp.cpu_num = 2;
		cpu_temp.temp[0] = *((volatile unsigned char *)temp_device.resource[0].end);
		cpu_temp.temp[1] = *((volatile unsigned char *)temp_device.resource[1].end);
	} else if (cpu_num == 4) {
		cpu_temp.cpu_num = 4;
		cpu_temp.temp[0] = *((volatile unsigned char *)temp_device.resource[0].end);
		cpu_temp.temp[1] = *((volatile unsigned char *)temp_device.resource[1].end);
		cpu_temp.temp[2] = *((volatile unsigned char *)temp_device.resource[2].end);
		cpu_temp.temp[3] = *((volatile unsigned char *)temp_device.resource[3].end);
	}
#endif
	mod_timer(&timer_temp, jiffies + 3 * HZ);

	return;

#if MODULE_ACTION
poweroff:
	printk(KERN_INFO "System will be poweroff.\n");
	pm_power_off();
#endif
}

static void check_temp_val(unsigned long data)
{
	int shift = CONFIG_NODES_SHIFT_LOONGSON;
	int cpu_num;

	if (cputype == Loongson_3A) {
		cpu_num = (1 << shift);
	} else {
		cpu_num = nr_cpu_loongson >> 3;
	}

	temp_handler(cpu_num);

	return;
}

static int probe_temp(struct platform_device *pdev)
{
	timer_temp.expires = jiffies + 3 * HZ;
	timer_temp.function = check_temp_val;
	timer_temp.data = (unsigned long)pdev;
	init_timer(&timer_temp);
	add_timer(&timer_temp);

	return 0;
}

static int remove_temp(struct platform_device *pdev)
{
	del_timer(&timer_temp);
	printk(KERN_INFO "Temperature protection function removed.\n");

	return 0;
}

static int __init platform_temp_init(void)
{
	platform_device_register(&temp_device);
	platform_driver_register(&temp_driver);

	return 0;
}

static void __exit platform_temp_exit(void)
{
	platform_device_unregister(&temp_device);
	platform_driver_unregister(&temp_driver);
}

module_init(platform_temp_init);
module_exit(platform_temp_exit);
