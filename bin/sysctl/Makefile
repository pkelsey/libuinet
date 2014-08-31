TOPDIR?=${CURDIR}/../..

PROG=sysctl

SRCS=sysctl.c u_sysctl.c

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/lib/libev -I../passive/ -I${TOPDIR}/lib/libuinetnv
LDADD= ${TOPDIR}/lib/libev/.libs/libev.a ${TOPDIR}/lib/libuinetnv/libuinetnv.a  -lm -lpcap

DEBUG_FLAGS=-g -O0

include ${TOPDIR}/mk/prog.mk
