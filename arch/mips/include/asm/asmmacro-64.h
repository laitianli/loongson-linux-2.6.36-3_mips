/*
 * asmmacro.h: Assembler macros to make things easier to read.
 *
 * Copyright (C) 1996 David S. Miller (dm@engr.sgi.com)
 * Copyright (C) 1998, 1999 Ralf Baechle
 * Copyright (C) 1999 Silicon Graphics, Inc.
 */
#ifndef _ASM_ASMMACRO_64_H
#define _ASM_ASMMACRO_64_H

#include <asm/asm-offsets.h>
#include <asm/regdef.h>
#include <asm/fpregdef.h>
#include <asm/mipsregs.h>

#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
#define gsexchange(vd, vs, vt, imm8) \
	.word ((0x1 << 29) | (vd << 22) | (vs << 15) | (vt << 8) | imm8)
#endif

	.macro	fpu_save_16even thread tmp=t0
	cfc1	\tmp, fcr31
	sdc1	$f0,  THREAD_FPR0(\thread)
	sdc1	$f2,  THREAD_FPR2(\thread)
	sdc1	$f4,  THREAD_FPR4(\thread)
	sdc1	$f6,  THREAD_FPR6(\thread)
	sdc1	$f8,  THREAD_FPR8(\thread)
	sdc1	$f10, THREAD_FPR10(\thread)
	sdc1	$f12, THREAD_FPR12(\thread)
	sdc1	$f14, THREAD_FPR14(\thread)
	sdc1	$f16, THREAD_FPR16(\thread)
	sdc1	$f18, THREAD_FPR18(\thread)
	sdc1	$f20, THREAD_FPR20(\thread)
	sdc1	$f22, THREAD_FPR22(\thread)
	sdc1	$f24, THREAD_FPR24(\thread)
	sdc1	$f26, THREAD_FPR26(\thread)
	sdc1	$f28, THREAD_FPR28(\thread)
	sdc1	$f30, THREAD_FPR30(\thread)
	sw	\tmp, THREAD_FCR31(\thread)
	.endm

	.macro	fpu_save_16odd thread
	sdc1	$f1,  THREAD_FPR1(\thread)
	sdc1	$f3,  THREAD_FPR3(\thread)
	sdc1	$f5,  THREAD_FPR5(\thread)
	sdc1	$f7,  THREAD_FPR7(\thread)
	sdc1	$f9,  THREAD_FPR9(\thread)
	sdc1	$f11, THREAD_FPR11(\thread)
	sdc1	$f13, THREAD_FPR13(\thread)
	sdc1	$f15, THREAD_FPR15(\thread)
	sdc1	$f17, THREAD_FPR17(\thread)
	sdc1	$f19, THREAD_FPR19(\thread)
	sdc1	$f21, THREAD_FPR21(\thread)
	sdc1	$f23, THREAD_FPR23(\thread)
	sdc1	$f25, THREAD_FPR25(\thread)
	sdc1	$f27, THREAD_FPR27(\thread)
	sdc1	$f29, THREAD_FPR29(\thread)
	sdc1	$f31, THREAD_FPR31(\thread)
	.endm

	.macro	fpu_save_double thread status tmp
	sll	\tmp, \status, 5
	bgez	\tmp, 2f
	fpu_save_16odd \thread
2:
	fpu_save_16even \thread \tmp
#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
        vpu_save_vect   \thread
#endif
	.endm

	.macro	fpu_restore_16even thread tmp=t0
	lw	\tmp, THREAD_FCR31(\thread)
	ldc1	$f0,  THREAD_FPR0(\thread)
	ldc1	$f2,  THREAD_FPR2(\thread)
	ldc1	$f4,  THREAD_FPR4(\thread)
	ldc1	$f6,  THREAD_FPR6(\thread)
	ldc1	$f8,  THREAD_FPR8(\thread)
	ldc1	$f10, THREAD_FPR10(\thread)
	ldc1	$f12, THREAD_FPR12(\thread)
	ldc1	$f14, THREAD_FPR14(\thread)
	ldc1	$f16, THREAD_FPR16(\thread)
	ldc1	$f18, THREAD_FPR18(\thread)
	ldc1	$f20, THREAD_FPR20(\thread)
	ldc1	$f22, THREAD_FPR22(\thread)
	ldc1	$f24, THREAD_FPR24(\thread)
	ldc1	$f26, THREAD_FPR26(\thread)
	ldc1	$f28, THREAD_FPR28(\thread)
	ldc1	$f30, THREAD_FPR30(\thread)
	ctc1	\tmp, fcr31
	.endm

	.macro	fpu_restore_16odd thread
	ldc1	$f1,  THREAD_FPR1(\thread)
	ldc1	$f3,  THREAD_FPR3(\thread)
	ldc1	$f5,  THREAD_FPR5(\thread)
	ldc1	$f7,  THREAD_FPR7(\thread)
	ldc1	$f9,  THREAD_FPR9(\thread)
	ldc1	$f11, THREAD_FPR11(\thread)
	ldc1	$f13, THREAD_FPR13(\thread)
	ldc1	$f15, THREAD_FPR15(\thread)
	ldc1	$f17, THREAD_FPR17(\thread)
	ldc1	$f19, THREAD_FPR19(\thread)
	ldc1	$f21, THREAD_FPR21(\thread)
	ldc1	$f23, THREAD_FPR23(\thread)
	ldc1	$f25, THREAD_FPR25(\thread)
	ldc1	$f27, THREAD_FPR27(\thread)
	ldc1	$f29, THREAD_FPR29(\thread)
	ldc1	$f31, THREAD_FPR31(\thread)
	.endm

	.macro	fpu_restore_double thread status tmp
	sll	\tmp, \status, 5
	bgez	\tmp, 1f				# 16 register mode?

	fpu_restore_16odd \thread
1:	fpu_restore_16even \thread \tmp
#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
        vpu_restore_vect   \thread
#endif
	.endm

	.macro	cpu_save_nonscratch thread
	LONG_S	s0, THREAD_REG16(\thread)
	LONG_S	s1, THREAD_REG17(\thread)
	LONG_S	s2, THREAD_REG18(\thread)
	LONG_S	s3, THREAD_REG19(\thread)
	LONG_S	s4, THREAD_REG20(\thread)
	LONG_S	s5, THREAD_REG21(\thread)
	LONG_S	s6, THREAD_REG22(\thread)
	LONG_S	s7, THREAD_REG23(\thread)
	LONG_S	sp, THREAD_REG29(\thread)
	LONG_S	fp, THREAD_REG30(\thread)
	.endm

	.macro	cpu_restore_nonscratch thread
	LONG_L	s0, THREAD_REG16(\thread)
	LONG_L	s1, THREAD_REG17(\thread)
	LONG_L	s2, THREAD_REG18(\thread)
	LONG_L	s3, THREAD_REG19(\thread)
	LONG_L	s4, THREAD_REG20(\thread)
	LONG_L	s5, THREAD_REG21(\thread)
	LONG_L	s6, THREAD_REG22(\thread)
	LONG_L	s7, THREAD_REG23(\thread)
	LONG_L	sp, THREAD_REG29(\thread)
	LONG_L	fp, THREAD_REG30(\thread)
	LONG_L	ra, THREAD_REG31(\thread)
	.endm


#ifdef CONFIG_CPU_SUPPORTS_VECTOR_COPROCESSOR
	/*
	 * Now define macro to save 32 VPU registers
	 */
	.macro	vpu_save_vect thread
	vstql	$z0, THREAD_VPR0(\thread)
	.word 0x4ae00007
	gsexchange(0, 0, 0, 1)
	vstql   $z0, (THREAD_VPR0+16)(\thread)

	vstql	$z1, THREAD_VPR1(\thread)
	.word 0x4ae00007
	gsexchange(1, 1, 1, 1)
	vstql   $z1, (THREAD_VPR1+16)(\thread)

	vstql	$z2, THREAD_VPR2(\thread)
	.word 0x4ae00007
	gsexchange(2, 2, 2, 1)
	vstql   $z2, (THREAD_VPR2+16)(\thread)

	vstql	$z3, THREAD_VPR3(\thread)
	.word 0x4ae00007
	gsexchange(3, 3, 3, 1)
	vstql   $z3, (THREAD_VPR3+16)(\thread)

	vstql	$z4, THREAD_VPR4(\thread)
	.word 0x4ae00007
	gsexchange(4, 4, 4, 1)
	vstql   $z4, (THREAD_VPR4+16)(\thread)

	vstql	$z5, THREAD_VPR5(\thread)
	.word 0x4ae00007
	gsexchange(5, 5, 5, 1)
	vstql   $z5, (THREAD_VPR5+16)(\thread)

	vstql	$z6, THREAD_VPR6(\thread)
	.word 0x4ae00007
	gsexchange(6, 6, 6, 1)
	vstql   $z6, (THREAD_VPR6+16)(\thread)

	vstql	$z7, THREAD_VPR7(\thread)
	.word 0x4ae00007
	gsexchange(7, 7, 7, 1)
	vstql   $z7, (THREAD_VPR7+16)(\thread)

	vstql	$z8, THREAD_VPR8(\thread)
	.word 0x4ae00007
	gsexchange(8, 8, 8, 1)
	vstql   $z8, (THREAD_VPR8+16)(\thread)

	vstql	$z9, THREAD_VPR9(\thread)
	.word 0x4ae00007
	gsexchange(9, 9, 9, 1)
	vstql   $z9, (THREAD_VPR9+16)(\thread)

	vstql	$z10, THREAD_VPR10(\thread)
	.word 0x4ae00007
	gsexchange(10, 10, 10, 1)
	vstql   $z10, (THREAD_VPR10+16)(\thread)

	vstql	$z11, THREAD_VPR11(\thread)
	.word 0x4ae00007
	gsexchange(11, 11, 11, 1)
	vstql 	$z11, (THREAD_VPR11+16)(\thread)

	vstql	$z12, THREAD_VPR12(\thread)
	.word 0x4ae00007
	gsexchange(12, 12, 12, 1)
	vstql 	$z12, (THREAD_VPR12+16)(\thread)

	vstql	$z13, THREAD_VPR13(\thread)
	.word 0x4ae00007
	gsexchange(13, 13, 13, 1)
	vstql 	$z13, (THREAD_VPR13+16)(\thread)

	vstql	$z14, THREAD_VPR14(\thread)
	.word 0x4ae00007
	gsexchange(14, 14, 14, 1)
	vstql 	$z14, (THREAD_VPR14+16)(\thread)

	vstql	$z15, THREAD_VPR15(\thread)
	.word 0x4ae00007
	gsexchange(15, 15, 15, 1)
	vstql 	$z15, (THREAD_VPR15+16)(\thread)

	vstql	$z16, THREAD_VPR16(\thread)
	.word 0x4ae00007
	gsexchange(16, 16, 16, 1)
	vstql 	$z16, (THREAD_VPR16+16)(\thread)

	vstql	$z17, THREAD_VPR17(\thread)
	.word 0x4ae00007
	gsexchange(17, 17, 17, 1)
	vstql 	$z17, (THREAD_VPR17+16)(\thread)

	vstql	$z18, THREAD_VPR18(\thread)
	.word 0x4ae00007
	gsexchange(18, 18, 18, 1)
	vstql 	$z18, (THREAD_VPR18+16)(\thread)

	vstql	$z19, THREAD_VPR19(\thread)
	.word 0x4ae00007
	gsexchange(19, 19, 19, 1)
	vstql 	$z19, (THREAD_VPR19+16)(\thread)

	vstql	$z20, THREAD_VPR20(\thread)
	.word 0x4ae00007
	gsexchange(20, 20, 20, 1)
	vstql 	$z20, (THREAD_VPR20+16)(\thread)

	vstql	$z21, THREAD_VPR21(\thread)
	.word 0x4ae00007
	gsexchange(21, 21, 21, 1)
	vstql 	$z21, (THREAD_VPR21+16)(\thread)

	vstql	$z22, THREAD_VPR22(\thread)
	.word 0x4ae00007
	gsexchange(22, 22, 22, 1)
	vstql 	$z22, (THREAD_VPR22+16)(\thread)

	vstql	$z23, THREAD_VPR23(\thread)
	.word 0x4ae00007
	gsexchange(23, 23, 23, 1)
	vstql 	$z23, (THREAD_VPR23+16)(\thread)

	vstql	$z24, THREAD_VPR24(\thread)
	.word 0x4ae00007
	gsexchange(24, 24, 24, 1)
	vstql 	$z24, (THREAD_VPR24+16)(\thread)

	vstql	$z25, THREAD_VPR25(\thread)
	.word 0x4ae00007
	gsexchange(25, 25, 25, 1)
	vstql 	$z25, (THREAD_VPR25+16)(\thread)

	vstql	$z26, THREAD_VPR26(\thread)
	.word 0x4ae00007
	gsexchange(26, 26, 26, 1)
	vstql 	$z26, (THREAD_VPR26+16)(\thread)

	vstql	$z27, THREAD_VPR27(\thread)
	.word 0x4ae00007
	gsexchange(27, 27, 27, 1)
	vstql 	$z27, (THREAD_VPR27+16)(\thread)

	vstql	$z28, THREAD_VPR28(\thread)
	.word 0x4ae00007
	gsexchange(28, 28, 28, 1)
	vstql 	$z28, (THREAD_VPR28+16)(\thread)

	vstql	$z29, THREAD_VPR29(\thread)
	.word 0x4ae00007
	gsexchange(29, 29, 29, 1)
	vstql 	$z29, (THREAD_VPR29+16)(\thread)

	vstql	$z30, THREAD_VPR30(\thread)
	.word 0x4ae00007
	gsexchange(30, 30, 30, 1)
	vstql 	$z30, (THREAD_VPR30+16)(\thread)

	vstql   $z31, THREAD_VPR31(\thread)
	.word 0x4ae00007
	gsexchange(31, 31, 31, 1)
	vstql   $z31, (THREAD_VPR31+16)(\thread)
	.endm

	/*
	 * Now define three micro to restore 32-128 VPU registers
	 */
	  .macro  vpu_restore_vect thread
	  vldql	  $z0, THREAD_VPR0(\thread)
	  vldql   $z127, (THREAD_VPR0+16)(\thread)
	.word 0x4ae00007
	  gsexchange(0, 0, 127, 32)

	  vldql	  $z1, THREAD_VPR1(\thread)
	  vldql   $z127, (THREAD_VPR1+16)(\thread)
	.word 0x4ae00007
	  gsexchange(1, 1, 127, 32)

	  vldql	  $z2, THREAD_VPR2(\thread)
	  vldql   $z127, (THREAD_VPR2+16)(\thread)
	.word 0x4ae00007
	  gsexchange(2, 2, 127, 32)

	  vldql	  $z3, THREAD_VPR3(\thread)
	  vldql   $z127, (THREAD_VPR3+16)(\thread)
	.word 0x4ae00007
	  gsexchange(3, 3, 127, 32)

	  vldql	  $z4, THREAD_VPR4(\thread)
	  vldql   $z127, (THREAD_VPR4+16)(\thread)
	.word 0x4ae00007
	  gsexchange(4, 4, 127, 32)

	  vldql	  $z5, THREAD_VPR5(\thread)
	  vldql   $z127, (THREAD_VPR5+16)(\thread)
	.word 0x4ae00007
	  gsexchange(5, 5, 127, 32)

	  vldql	  $z6, THREAD_VPR6(\thread)
	  vldql   $z127, (THREAD_VPR6+16)(\thread)
	.word 0x4ae00007
	  gsexchange(6, 6, 127, 32)

	  vldql	  $z7, THREAD_VPR7(\thread)
	  vldql   $z127, (THREAD_VPR7+16)(\thread)
	.word 0x4ae00007
	  gsexchange(7, 7, 127, 32)

	  vldql	  $z8, THREAD_VPR8(\thread)
	  vldql   $z127, (THREAD_VPR8+16)(\thread)
	.word 0x4ae00007
	  gsexchange(8, 8, 127, 32)

	  vldql	  $z9, THREAD_VPR9(\thread)
	  vldql   $z127, (THREAD_VPR9+16)(\thread)
	.word 0x4ae00007
	  gsexchange(9, 9, 127, 32)

	  vldql	  $z10, THREAD_VPR10(\thread)
	  vldql   $z127, (THREAD_VPR10+16)(\thread)
	.word 0x4ae00007
	  gsexchange(10, 10, 127, 32)

	  vldql	  $z11, THREAD_VPR11(\thread)
	  vldql   $z127, (THREAD_VPR11+16)(\thread)
	.word 0x4ae00007
	  gsexchange(11, 11, 127, 32)

	  vldql	  $z12, THREAD_VPR12(\thread)
	  vldql   $z127, (THREAD_VPR12+16)(\thread)
	.word 0x4ae00007
	  gsexchange(12, 12, 127, 32)

	  vldql	  $z13, THREAD_VPR13(\thread)
	  vldql   $z127, (THREAD_VPR13+16)(\thread)
	.word 0x4ae00007
	  gsexchange(13, 13, 127, 32)

	  vldql	  $z14, THREAD_VPR14(\thread)
	  vldql   $z127, (THREAD_VPR14+16)(\thread)
	.word 0x4ae00007
	  gsexchange(14, 14, 127, 32)

	  vldql	  $z15, THREAD_VPR15(\thread)
	  vldql   $z127, (THREAD_VPR15+16)(\thread)
	.word 0x4ae00007
	  gsexchange(15, 15, 127, 32)

	  vldql	  $z16, THREAD_VPR16(\thread)
	  vldql   $z127, (THREAD_VPR16+16)(\thread)
	.word 0x4ae00007
	  gsexchange(16, 16, 127, 32)

	  vldql	  $z17, THREAD_VPR17(\thread)
	  vldql   $z127, (THREAD_VPR17+16)(\thread)
	.word 0x4ae00007
	  gsexchange(17, 17, 127, 32)

	  vldql	  $z18, THREAD_VPR18(\thread)
	  vldql   $z127, (THREAD_VPR18+16)(\thread)
	.word 0x4ae00007
	  gsexchange(18, 18, 127, 32)

	  vldql	  $z19, THREAD_VPR19(\thread)
	  vldql   $z127, (THREAD_VPR19+16)(\thread)
	.word 0x4ae00007
	  gsexchange(19, 19, 127, 32)

	  vldql	  $z20, THREAD_VPR20(\thread)
	  vldql   $z127, (THREAD_VPR20+16)(\thread)
	.word 0x4ae00007
	  gsexchange(20, 20, 127, 32)

	  vldql	  $z21, THREAD_VPR21(\thread)
	  vldql   $z127, (THREAD_VPR21+16)(\thread)
	.word 0x4ae00007
	  gsexchange(21, 21, 127, 32)

	  vldql	  $z22, THREAD_VPR22(\thread)
	  vldql   $z127, (THREAD_VPR22+16)(\thread)
	.word 0x4ae00007
	  gsexchange(22, 22, 127, 32)

	  vldql	  $z23, THREAD_VPR23(\thread)
	  vldql   $z127, (THREAD_VPR23+16)(\thread)
	.word 0x4ae00007
	  gsexchange(23, 23, 127, 32)

	  vldql	  $z24, THREAD_VPR24(\thread)
	  vldql   $z127, (THREAD_VPR24+16)(\thread)
	.word 0x4ae00007
	  gsexchange(24, 24, 127, 32)

	  vldql	  $z25, THREAD_VPR25(\thread)
	  vldql   $z127, (THREAD_VPR25+16)(\thread)
	.word 0x4ae00007
	  gsexchange(25, 25, 127, 32)

	  vldql	  $z26, THREAD_VPR26(\thread)
	  vldql   $z127, (THREAD_VPR26+16)(\thread)
	.word 0x4ae00007
	  gsexchange(26, 26, 127, 32)

	  vldql	  $z27, THREAD_VPR27(\thread)
	  vldql   $z127, (THREAD_VPR27+16)(\thread)
	.word 0x4ae00007
	  gsexchange(27, 27, 127, 32)

	  vldql	  $z28, THREAD_VPR28(\thread)
	  vldql   $z127, (THREAD_VPR28+16)(\thread)
	.word 0x4ae00007
	  gsexchange(28, 28, 127, 32)

	  vldql	  $z29, THREAD_VPR29(\thread)
	  vldql   $z127, (THREAD_VPR29+16)(\thread)
	.word 0x4ae00007
	  gsexchange(29, 29, 127, 32)

	  vldql	  $z30, THREAD_VPR30(\thread)
	  vldql   $z127, (THREAD_VPR30+16)(\thread)
	.word 0x4ae00007
	  gsexchange(30, 30, 127, 32)

	  vldql	  $z31, THREAD_VPR31(\thread)
	  vldql   $z127, (THREAD_VPR31+16)(\thread)
	.word 0x4ae00007
	  gsexchange(31, 31, 127, 32)
	  .endm
#endif
#endif /* _ASM_ASMMACRO_64_H */
