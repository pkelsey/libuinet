TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/cflags.mk

PROG=tproxy

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/lib/libev
LDADD= -L${UINET_DESTDIR}/lib/ ${TOPDIR}/lib/libev/.libs/libev.a -lm -lpcap

include ${TOPDIR}/mk/prog.mk
