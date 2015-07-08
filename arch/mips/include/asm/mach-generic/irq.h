/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2003 by Ralf Baechle
 */
#ifndef __ASM_MACH_GENERIC_IRQ_H
#define __ASM_MACH_GENERIC_IRQ_H

#ifndef NR_IRQS
#if defined(CONFIG_LS2H_SOUTHBRIDGE) || defined(CONFIG_CPU_LOONGSON2H)
#define NR_IRQS	256
#else
#define NR_IRQS	128
#endif
#endif

#ifdef CONFIG_I8259
#ifndef I8259A_IRQ_BASE
#define I8259A_IRQ_BASE	0
#endif
#endif

#ifdef CONFIG_IRQ_CPU

#if defined(CONFIG_LS2H_SOUTHBRIDGE) || defined(CONFIG_CPU_LOONGSON2H)
#define MIPS_CPU_IRQ_BASE 56  
#endif

#ifndef MIPS_CPU_IRQ_BASE
#ifdef CONFIG_I8259 
#ifdef CONFIG_CPU_LOONGSON3 
#define MIPS_CPU_IRQ_BASE 56  //cww??
#else
#define MIPS_CPU_IRQ_BASE 16
#endif
#else
#define MIPS_CPU_IRQ_BASE 0
#endif /* CONFIG_I8259 */
#endif

#ifdef CONFIG_IRQ_CPU_RM7K
#ifndef RM7K_CPU_IRQ_BASE
#define RM7K_CPU_IRQ_BASE (MIPS_CPU_IRQ_BASE+8)
#endif
#endif

#ifdef CONFIG_IRQ_CPU_RM9K
#ifndef RM9K_CPU_IRQ_BASE
#define RM9K_CPU_IRQ_BASE (MIPS_CPU_IRQ_BASE+12)
#endif
#endif

#endif /* CONFIG_IRQ_CPU */

#endif /* __ASM_MACH_GENERIC_IRQ_H */
