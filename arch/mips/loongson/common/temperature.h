#ifndef _TEMPERATURE_H_
#define _TEMPERATURE_H_

#define MODULE_ACTION	1
#define PROC_PRINT		1

struct temperature {
	int cpu_num;
	unsigned char temp[4];
} __packed;

extern struct temperature cpu_temp;
extern unsigned long long poweroff_addr;
extern unsigned int CONFIG_NODES_SHIFT_LOONGSON;
#endif
