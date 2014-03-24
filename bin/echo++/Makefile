

TOPDIR?=${CURDIR}/../..

PROG_CXX=echo++

UINET_LIBS=uinet

CXXFLAGS= -I${TOPDIR}/lib/libev
LDADD= ${TOPDIR}/lib/libev/.libs/libev.a -lm -lpcap

DEBUG_FLAGS=-g -O0

include ${TOPDIR}/mk/prog.mk
