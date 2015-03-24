TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/cflags.mk

PROG=multitool

UINET_LIBS=ev http_parser uinet_demo uinet

LDADD= -L${UINET_DESTDIR}/lib/ -lm -lpcap

include ${TOPDIR}/mk/prog.mk
