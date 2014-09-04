

TOPDIR?=${CURDIR}/../..

PROG=poolspeed

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/lib/libev
LDADD= ${TOPDIR}/lib/libev/.libs/libev.a -lm -lpcap

DEBUG_FLAGS=-g -O2

include ${TOPDIR}/mk/prog.mk
