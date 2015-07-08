#ifndef _ASM_MACH_TOPOLOGY_H
#define _ASM_MACH_TOPOLOGY_H	1

#ifdef CONFIG_NUMA
#define cpu_to_node(cpu)	((cpu) >> 2)
#define parent_node(node)	(node)
#define cpumask_of_node(node)	(&__node_data[(node)]->cpumask)

struct cpuinfo_loongson3 {
	//cpuid_t	p_cpuid;	/* PROM assigned cpuid */
	unsigned int	p_nodeid;	/* my node ID in compact-id-space */
	unsigned char	p_slice;	/* Physical position on node board */
#if 0
	unsigned long		loops_per_sec;
	unsigned long		ipi_count;
	unsigned long		irq_attempt[NR_IRQS];
	unsigned long		smp_local_irq_count;
	unsigned long		prof_multiplier;
	unsigned long		prof_counter;
#endif
};

extern struct cpuinfo_loongson3 sn_cpu_info[NR_CPUS];
struct pci_bus;
extern int pcibus_to_node(struct pci_bus *);

#define cpumask_of_pcibus(bus)	(cpu_online_mask)

extern unsigned char __node_distances[MAX_NUMNODES][MAX_NUMNODES];

#define node_distance(from, to)	(__node_distances[(from)][(to)])

/* sched_domains SD_NODE_INIT for LOONGSON3 machines */
#define SD_NODE_INIT (struct sched_domain) {		\
	.parent			= NULL,			\
	.child			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 8,			\
	.max_interval		= 32,			\
	.busy_factor		= 32,			\
	.imbalance_pct		= 125,			\
	.cache_nice_tries	= 1,			\
	.flags			= SD_LOAD_BALANCE |	\
				SD_BALANCE_EXEC,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}
#endif

#include <asm-generic/topology.h>

#endif /* _ASM_MACH_TOPOLOGY_H */
