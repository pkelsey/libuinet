include cflags.mk

SUBDIRS=lib bin

config all clean install maintainer-clean:
	for d in $(SUBDIRS); do ( cd $$d && $(MAKE) $@) ||  exit 1 ; done
	if [ "$@" = "all" -o "$@" = "install" ] ; then $(MAKE) $@-extra ; fi
	#if [ "$@" = "all" ] ; then rm -f version.extended ; $(MAKE) version.extended ; fi
easy_start: config all

.PHONY: version.extended

all-extra: version.extended

install-extra:
	mkdir -p ${UINET_DESTDIR}/etc/libuinet
	cp version.extended ${UINET_DESTDIR}/etc/libuinet/version.extended

version.extended:
	echo "buildroot: ${CURDIR}" > $@
	echo "date: `date`" >> $@
	echo "git-sha: `git rev-parse --short HEAD`" >> $@
	echo "git-branch: `git rev-parse --abbrev-ref HEAD`" >> $@
