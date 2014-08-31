
TOPDIR?=${CURDIR}/../..
include ${TOPDIR}/lib.mk
include ${TOPDIR}/cflags.mk

CFLAGS+=	${DEBUG_FLAGS}

SRCS=	dnvlist.c msgio.c nvlist.c nvpair.c
OBJS=	dnvlist.o msgio.o nvlist.o nvpair.o
INCS=	uinet_dnv.h uinet_nv.h

all: libuinetnv.a

libuinetnv.a: $(OBJS)
	$(AR) -c -r libuinetnv.a $(OBJS)

clean:
	$(RM) $(OBJS) libuinetnv.a

install:
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/lib
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/include/nv
	${UINET_INSTALL_LIB} libuinetnv.a ${UINET_DESTDIR}/lib
	${UINET_INSTALL_INC} uinet_dnv.h ${UINET_DESTDIR}/include/nv
	${UINET_INSTALL_INC} uinet_nv.h ${UINET_DESTDIR}/include/nv
