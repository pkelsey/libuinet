# $FreeBSD: release/9.1.0/sys/crypto/rijndael/Makefile 139103 2004-12-21 08:47:35Z ru $

PROG=test00
NO_MAN=
SRCS= ${PROG}.c rijndael-alg-fst.c rijndael-api-fst.c

CFLAGS += -I${.CURDIR}/../.. -g -static

.include <bsd.prog.mk>

test:	${PROG}
	./${PROG}
