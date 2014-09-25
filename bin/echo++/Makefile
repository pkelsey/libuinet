TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/cflags.mk

PROG_CXX=echo++

UINET_LIBS=uinet

CXXFLAGS= -I${TOPDIR}/lib/libev
LDADD= -L${UINET_DESTDIR}/lib/ ${TOPDIR}/lib/libev/.libs/libev.a -lm -lpcap

include ${TOPDIR}/mk/prog.mk
