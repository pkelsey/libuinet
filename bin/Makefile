TOPDIR?=${CURDIR}/..
include ${TOPDIR}/cflags.mk

SUBDIRS=echo echo++ passive tproxy
ifeq (${HOST_OS},FreeBSD)
SUBDIRS+=sysctl vmstat 
endif

config:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) config ) ; done

all:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) all ) ; done

clean:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) clean ) ; done

install:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) install ) ; done

