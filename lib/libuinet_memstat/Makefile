
TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/lib.mk
include ${TOPDIR}/cflags.mk

CFLAGS+=	${DEBUG_FLAGS}
CFLAGS+=	-I${TOPDIR}/lib/libuinet/api_include/ -I${TOPDIR}/lib/libuinetnv/

SRCS=	memstat.c memstat_all.c memstat_malloc.c memstat_uma.c u_sysctl.c
OBJS=	memstat.o memstat_all.o memstat_malloc.o memstat_uma.o u_sysctl.o
INCS=	memstat.h

all: libuinet_memstat.a

libuinet_memstat.a: $(OBJS)
	$(AR) -c -r libuinet_memstat.a $(OBJS)

clean:
	$(RM) $(OBJS) libuinet_memstat.a

install:
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/lib
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/include/memstat
	${UINET_INSTALL_LIB} libuinet_memstat.a ${UINET_DESTDIR}/lib
	${UINET_INSTALL_INC} memstat.h ${UINET_DESTDIR}/include/memstat
