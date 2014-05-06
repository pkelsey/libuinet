

TOPDIR?=${CURDIR}/../..

PROG=passive

UINET_LIBS=uinet

CFLAGS= -I${TOPDIR}/lib/libev
LDADD= ${TOPDIR}/lib/libev/.libs/libev.a -lm -lpcap

ifndef NO_EXTRACT
CFLAGS+= -I${TOPDIR}/lib/libhttp_parser -DENABLE_EXTRACT
LDADD+=  -L${TOPDIR}/lib/libhttp_parser -lhttp_parser -lz
endif


DEBUG_FLAGS=-g -O0

include ${TOPDIR}/mk/prog.mk
