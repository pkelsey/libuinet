
SUBDIRS=echo echo++ passive sysctl tproxy vmstat

config:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) config ) ; done

all:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) all ) ; done

clean:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) clean ) ; done

install:
	for d in $(SUBDIRS); do ( cd $$d; $(MAKE) install ) ; done

