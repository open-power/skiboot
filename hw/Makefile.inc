# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS  = xscom.o chiptod.o gx.o cec.o lpc.o lpc-uart.o psi.o
HW_OBJS += homer.o slw.o occ.o nx.o fsi-master.o centaur.o
HW_OBJS += p7ioc.o p7ioc-inits.o p7ioc-phb.o p5ioc2.o p5ioc2-phb.o
HW_OBJS += phb3.o sfc-ctrl.o fake-rtc.o
HW=hw/built-in.o

include $(SRC)/hw/fsp/Makefile.inc
include $(SRC)/hw/ec/Makefile.inc
include $(SRC)/hw/ast-bmc/Makefile.inc

$(HW): $(HW_OBJS:%=hw/%) $(FSP) $(EC) $(AST_BMC)

