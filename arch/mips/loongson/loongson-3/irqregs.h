#ifndef __IRQREGS__H__
#define __IRQREGS__H__

#include <boot_param.h>

#define LOONGSON_INT_BIT_INT0		(1 << 11)
#define LOONGSON_INT_BIT_INT1		(1 << 12)

#define LOONGSON3_INT_BIT_HT_INT0	loongson_int_bit_ht_int0
#define IO_base_regs_addr 		 io_base_regs_addr

#define	smp_core_group0_base	smp_group0
#define	smp_core_group1_base	smp_group1
#define	smp_core_group2_base	smp_group2
#define	smp_core_group3_base	smp_group3

#define IO_control_regs_Intisr		*(volatile unsigned int *)(IO_base_regs_addr + 0x1420)
#define IO_control_regs_Inten		*(volatile unsigned int *)(IO_base_regs_addr + 0x1424)
#define IO_control_regs_Intenset	*(volatile unsigned int *)(IO_base_regs_addr + 0x1428)
#define IO_control_regs_Intenclr	*(volatile unsigned int *)(IO_base_regs_addr + 0x142c)
#define IO_control_regs_Intedge		*(volatile unsigned int *)(IO_base_regs_addr + 0x1438)
#define IO_control_regs_CORE0_INTISR	*(volatile unsigned int *)(IO_base_regs_addr + 0x1440)
#define IO_control_regs_CORE1_INTISR	*(volatile unsigned int *)(IO_base_regs_addr + 0x1448)
#define IO_control_regs_CORE2_INTISR	*(volatile unsigned int *)(IO_base_regs_addr + 0x1450)
#define IO_control_regs_CORE3_INTISR	*(volatile unsigned int *)(IO_base_regs_addr + 0x1458)

#define INT_router_regs_sys_int0	*(volatile unsigned char *)(IO_base_regs_addr + 0x1400)
#define INT_router_regs_sys_int1	*(volatile unsigned char *)(IO_base_regs_addr + 0x1401)
#define INT_router_regs_sys_int2	*(volatile unsigned char *)(IO_base_regs_addr + 0x1402)
#define INT_router_regs_sys_int3	*(volatile unsigned char *)(IO_base_regs_addr + 0x1403)
#define INT_router_regs_pci_int0	*(volatile unsigned char *)(IO_base_regs_addr + 0x1404)
#define INT_router_regs_pci_int1	*(volatile unsigned char *)(IO_base_regs_addr + 0x1405)
#define INT_router_regs_pci_int2	*(volatile unsigned char *)(IO_base_regs_addr + 0x1406)
#define INT_router_regs_pci_int3	*(volatile unsigned char *)(IO_base_regs_addr + 0x1407)
#define INT_router_regs_matrix_int0	*(volatile unsigned char *)(IO_base_regs_addr + 0x1408)
#define INT_router_regs_matrix_int1	*(volatile unsigned char *)(IO_base_regs_addr + 0x1409)
#define INT_router_regs_lpc_int		*(volatile unsigned char *)(IO_base_regs_addr + 0x140a)
#define INT_router_regs_mc0		*(volatile unsigned char *)(IO_base_regs_addr + 0x140b)
#define INT_router_regs_mc1		*(volatile unsigned char *)(IO_base_regs_addr + 0x140c)
#define INT_router_regs_barrier		*(volatile unsigned char *)(IO_base_regs_addr + 0x140d)
#define INT_router_regs_reserve		*(volatile unsigned char *)(IO_base_regs_addr + 0x140e)
#define INT_router_regs_pci_perr	*(volatile unsigned char *)(IO_base_regs_addr + 0x140f)

#define INT_router_regs_HT0_int0	*(volatile unsigned char *)(IO_base_regs_addr + 0x1410)
#define INT_router_regs_HT0_int1	*(volatile unsigned char *)(IO_base_regs_addr + 0x1411)
#define INT_router_regs_HT0_int2	*(volatile unsigned char *)(IO_base_regs_addr + 0x1412)
#define INT_router_regs_HT0_int3	*(volatile unsigned char *)(IO_base_regs_addr + 0x1413)
#define INT_router_regs_HT0_int4	*(volatile unsigned char *)(IO_base_regs_addr + 0x1414)
#define INT_router_regs_HT0_int5	*(volatile unsigned char *)(IO_base_regs_addr + 0x1415)
#define INT_router_regs_HT0_int6	*(volatile unsigned char *)(IO_base_regs_addr + 0x1416)
#define INT_router_regs_HT0_int7	*(volatile unsigned char *)(IO_base_regs_addr + 0x1417)
#define INT_router_regs_HT1_int0	*(volatile unsigned char *)(IO_base_regs_addr + 0x1418)
#define INT_router_regs_HT1_int1	*(volatile unsigned char *)(IO_base_regs_addr + 0x1419)
#define INT_router_regs_HT1_int2	*(volatile unsigned char *)(IO_base_regs_addr + 0x141a)
#define INT_router_regs_HT1_int3	*(volatile unsigned char *)(IO_base_regs_addr + 0x141b)
#define INT_router_regs_HT1_int4	*(volatile unsigned char *)(IO_base_regs_addr + 0x141c)
#define INT_router_regs_HT1_int5	*(volatile unsigned char *)(IO_base_regs_addr + 0x141d)
#define INT_router_regs_HT1_int6	*(volatile unsigned char *)(IO_base_regs_addr + 0x141e)
#define INT_router_regs_HT1_int7	*(volatile unsigned char *)(IO_base_regs_addr + 0x141f)

#define Local_IO_regs_Base		0xffffffffbfe00000 
#define LPC_INT_regs_ctrl		*(volatile unsigned int *)(Local_IO_regs_Base + 0x0200)
#define LPC_INT_regs_enable		*(volatile unsigned int *)(Local_IO_regs_Base + 0x0204)
#define LPC_INT_regs_status		*(volatile unsigned int *)(Local_IO_regs_Base + 0x0208)
#define LPC_INT_regs_clear		*(volatile unsigned int *)(Local_IO_regs_Base + 0x020c)

#endif
