

TOPDIR?=${CURDIR}/../../../..

PROG=echo

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/network/uinet/lib/libev
LDFLAGS= ${TOPDIR}/network/uinet/lib/libev/.libs/libev.a ${TOPDIR}/network/uinet/lib/libev/.libs/ev.o -lm

DEBUG_FLAGS=-g -O0

include $(TOPDIR)/network/uinet/mk/prog.mk
