TOPDIR?=${CURDIR}/..
include ${TOPDIR}/cflags.mk

SUBDIRS=echo echo++ passive tproxy
ifeq (${HOST_OS},FreeBSD)
SUBDIRS+=sysctl vmstat 
endif

config all clean install maintainer-clean:
	for d in $(SUBDIRS); do ( cd $$d && $(MAKE) $@) ||  exit 1 ; done
