#ifndef _BUS_DEMO_H_
#define _BUS_DEMO_H_

#ifndef BUS_ID_SIZE
#define BUS_ID_SIZE 20
#endif

int bus_demo_register(void);

void bus_demo_unregister(void);

struct bus_type* get_bus_demo(void);

struct device* get_bus_demo_dev(void);

#endif

