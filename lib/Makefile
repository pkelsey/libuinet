TOPDIR?=${CURDIR}/..
include ${TOPDIR}/cflags.mk

SUBDIRS=libuinet libev libhttp_parser
ifeq (${HOST_OS},FreeBSD)
SUBDIRS+=libuinetnv libuinet_memstat 
endif

default: all

config:
	(cd libev ; env CFLAGS="${DEBUG_FLAGS}" ./configure --with-uinet=../libuinet/api_include --prefix="${UINET_DESTDIR}" --includedir="${UINET_DESTDIR}/include/libev" --enable-shared=no )

all:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) all ) ; done

clean:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) clean ) ; done

install:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) install ) ; done

default: config all
