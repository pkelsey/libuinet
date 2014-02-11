

TOPDIR?=${CURDIR}/../../../..

PROG=echo

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/network/uinet/lib/libev
LDADD= ${TOPDIR}/network/uinet/lib/libev/.libs/libev.a -lm

DEBUG_FLAGS=-g -O0

include $(TOPDIR)/network/uinet/mk/prog.mk
