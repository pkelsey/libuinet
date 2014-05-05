

TOPDIR?=${CURDIR}/../..

PROG=passive

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/lib/libev -I${TOPDIR}/lib/libhttp_parser
LDADD= ${TOPDIR}/lib/libev/.libs/libev.a -lm -lpcap -L${TOPDIR}/lib/libhttp_parser -lhttp_parser -lz

DEBUG_FLAGS=-g -O0

include ${TOPDIR}/mk/prog.mk
