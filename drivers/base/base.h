
/**
 * struct bus_type_private - structure to hold the private to the driver core portions of the bus_type structure.
 *
 * @subsys - the struct kset that defines this bus.  This is the main kobject
 * @drivers_kset - the list of drivers associated with this bus
 * @devices_kset - the list of devices associated with this bus
 * @klist_devices - the klist to iterate over the @devices_kset
 * @klist_drivers - the klist to iterate over the @drivers_kset
 * @bus_notifier - the bus notifier list for anything that cares about things
 * on this bus.
 * @bus - pointer back to the struct bus_type that this structure is associated
 * with.
 *
 * This structure is the one that is the actual kobject allowing struct
 * bus_type to be statically allocated safely.  Nothing outside of the driver
 * core should ever touch these fields.
 */
 /*总线的私有数据结构*/
struct bus_type_private {
	struct kset subsys;
	struct kset *drivers_kset;
	struct kset *devices_kset;
	struct klist klist_devices;	/*此总线上的设备列表*/
	struct klist klist_drivers; /*此总线上的驱动列表*/
	struct blocking_notifier_head bus_notifier;
	unsigned int drivers_autoprobe:1;
	struct bus_type *bus;//所属总线
};
/*驱动的私有数据结构*/
struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;/*作为链表头*/
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;/*所属的驱动对象*/
};
#define to_driver(obj) container_of(obj, struct driver_private, kobj)


/**
 * struct class_private - structure to hold the private to the driver core portions of the class structure.
 *
 * @class_subsys - the struct kset that defines this class.  This is the main kobject
 * @class_devices - list of devices associated with this class
 * @class_interfaces - list of class_interfaces associated with this class
 * @class_dirs - "glue" directory for virtual devices associated with this class
 * @class_mutex - mutex to protect the children, devices, and interfaces lists.
 * @class - pointer back to the struct class that this structure is associated
 * with.
 *
 * This structure is the one that is the actual kobject allowing struct
 * class to be statically allocated safely.  Nothing outside of the driver
 * core should ever touch these fields.
 */
/*类私有数据*/
struct class_private {
	struct kset class_subsys;
	struct klist class_devices;
	struct list_head class_interfaces;
	struct kset class_dirs;
	struct mutex class_mutex;
	struct class *class;
};
#define to_class(obj)	\
	container_of(obj, struct class_private, class_subsys.kobj)

/**
 * struct device_private - structure to hold the private to the driver core portions of the device structure.
 *
 * @klist_children - klist containing all children of this device
 * @knode_parent - node in sibling list
 * @knode_driver - node in driver list
 * @knode_bus - node in bus list
 * @driver_data - private pointer for driver specific info.  Will turn into a
 * list soon.
 * @device - pointer back to the struct class that this structure is
 * associated with.
 *
 * Nothing outside of the driver core should ever touch these fields.
 */
/*设备私有数据结构*/
struct device_private {
	struct klist klist_children;	/*knode_parent的链表头,表示当前设备的子设备*/
	struct klist_node knode_parent; /*做连接件使用，链表头为klist_children*/
	struct klist_node knode_driver; /*做连接件使用，链表头为driver_private:klist_devices*/
	struct klist_node knode_bus;/*做连接件使用，链表头为driver_private:klist_devices*/
	void *driver_data;	//私有数据
	struct device *device;//所性的设备对象
};
#define to_device_private_parent(obj)	\
	container_of(obj, struct device_private, knode_parent)
#define to_device_private_driver(obj)	\
	container_of(obj, struct device_private, knode_driver)
#define to_device_private_bus(obj)	\
	container_of(obj, struct device_private, knode_bus)

extern int device_private_init(struct device *dev);

/* initialisation functions */
extern int devices_init(void);
extern int buses_init(void);
extern int classes_init(void);
extern int firmware_init(void);
#ifdef CONFIG_SYS_HYPERVISOR
extern int hypervisor_init(void);
#else
static inline int hypervisor_init(void) { return 0; }
#endif
extern int platform_bus_init(void);
extern int system_bus_init(void);
extern int cpu_dev_init(void);

extern int bus_add_device(struct device *dev);
extern void bus_probe_device(struct device *dev);
extern void bus_remove_device(struct device *dev);

extern int bus_add_driver(struct device_driver *drv);
extern void bus_remove_driver(struct device_driver *drv);

extern void driver_detach(struct device_driver *drv);
extern int driver_probe_device(struct device_driver *drv, struct device *dev);
static inline int driver_match_device(struct device_driver *drv,
				      struct device *dev)
{
	return drv->bus->match ? drv->bus->match(dev, drv) : 1;
}

extern void sysdev_shutdown(void);

extern char *make_class_name(const char *name, struct kobject *kobj);

extern int devres_release_all(struct device *dev);

extern struct kset *devices_kset;

#if defined(CONFIG_MODULES) && defined(CONFIG_SYSFS)
extern void module_add_driver(struct module *mod, struct device_driver *drv);
extern void module_remove_driver(struct device_driver *drv);
#else
static inline void module_add_driver(struct module *mod,
				     struct device_driver *drv) { }
static inline void module_remove_driver(struct device_driver *drv) { }
#endif

#ifdef CONFIG_DEVTMPFS
extern int devtmpfs_init(void);
#else
static inline int devtmpfs_init(void) { return 0; }
#endif
