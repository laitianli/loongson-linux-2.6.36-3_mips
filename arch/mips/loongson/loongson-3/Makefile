#
# Makefile for ICT CAS loongson3a board.
#

#obj-y	+= setup.o prom.o reset.o irq.o pci.o bonito-irq.o mipsdha.o dbg_io.o mem.o 
obj-y	+= irq.o dbg_io.o rs780e-irq.o pci.o

obj-$(CONFIG_SMP)	+= smp.o

obj-$(CONFIG_NUMA)	+= numa.o
obj-$(CONFIG_LS2H_SOUTHBRIDGE)	+= ls2h-irq.o platform.o
ifdef CONFIG_LS2H_SOUTHBRIDGE
obj-$(CONFIG_PCI)	+= ls2h-pci.o
endif
#EXTRA_AFLAGS := $(CFLAGS)
