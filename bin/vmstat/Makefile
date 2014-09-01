TOPDIR?=${CURDIR}/../..

PROG=vmstat

SRCS=vmstat_zmemstat.c vmstat_memstat.c vmstat_main.c

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/lib/libuinet_memstat
LDADD= ${TOPDIR}/lib/libuinet_memstat/libuinet_memstat.a ${TOPDIR}/lib/libuinetnv/libuinetnv.a

DEBUG_FLAGS=-g -O0

include ${TOPDIR}/mk/prog.mk
