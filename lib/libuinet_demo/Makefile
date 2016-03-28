TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/cflags.mk

LIB=uinet_demo

SRCS+=				\
	uinet_demo.c 		\
	uinet_demo_connscale.c	\
	uinet_demo_echo.c	\
	uinet_demo_nproxy.c	\
	uinet_demo_passive.c	\
	uinet_demo_passive_extract.c	\
	uinet_demo_util.c

UINET_LIBS=ev http_parser uinet

include ${TOPDIR}/mk/lib.mk
