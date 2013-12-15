#
# Derived from FreeBSD auto-generated kernel Makefile and
# machine-specific Makefile templates
#
DEBUG=-ggdb -O0

TOPDIR?=${CURDIR}/../../../..
S=${TOPDIR}/network/uinet/sys
API_INCLUDES_ROOT:=${CURDIR}/api_include
MACHINE_INCLUDES_ROOT:=${CURDIR}/machine_include
OVERRIDE_INCLUDES_ROOT:=${CURDIR}/override_include
X86_INCLUDES=0

include ${TOPDIR}/network/uinet/mk/kern.pre.mk

KERNPREINCLUDES:= ${INCLUDES}
INCLUDES= -I${OVERRIDE_INCLUDES_ROOT} -I${API_INCLUDES_ROOT} ${KERNPREINCLUDES}
INCLUDES+= -I./machine_include
INCLUDES+= -I./opt

# Include search path for files that only include host OS headers
HOST_INCLUDES= -I. -I${API_INCLUDES_ROOT} 

ifdef NETMAP_INCLUDES
HOST_INCLUDES+= -I${NETMAP_INCLUDES}
endif

HOST_C= ${CC} -c ${CFLAGS} ${HOST_INCLUDES} ${WERROR} ${PROF} $<


ifneq ($(filter amd64 i386,${MACHINE_CPUARCH}),)
X86_INCLUDES=1
endif


#
# Distilled from FreeBSD src/sys/conf/Makefile.amd64
#
ifeq (${MACHINE_CPUARCH},amd64)
endif

#
# Distilled from FreeBSD src/sys/conf/Makefile.arm
#
ifeq (${MACHINE_CPUARCH},arm)

ifneq (${COMPILER_TYPE},clang)
CFLAGS += -mno-thumb-interwork
endif

endif


#
# Distilled from FreeBSD src/sys/conf/Makefile.i386
#
ifeq (${MACHINE_CPUARCH},i386)
MACHINE=i386
endif


#
# Distilled from FreeBSD src/sys/conf/Makefile.mips
#
ifeq (${MACHINE_CPUARCH},mips)

# We default to the MIPS32 ISA, if none specified in the
# kernel configuration file.
ARCH_FLAGS?=-march=mips32

HACK_EXTRA_FLAGS=-shared

CFLAGS+=${EXTRA_FLAGS} $(ARCH_FLAGS)
HACK_EXTRA_FLAGS+=${EXTRA_FLAGS} $(ARCH_FLAGS)
endif


CFLAGS+= -DUINET=1

VPATH+= $S/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}
VPATH+= $S/kern
VPATH+= $S/crypto
VPATH+= $S/net
VPATH+= $S/netinet
VPATH+= $S/netinet/cc
VPATH+= $S/vm
VPATH+= $S/libkern


UINET_SRCS+=			\
	uinet_api.c		\
	uinet_clock.c		\
	uinet_config.c		\
	uinet_config_kernel.c	\
	uinet_elf_machdep.c	\
	uinet_init.c		\
	uinet_init_main.c	\
	uinet_kern_clock.c	\
	uinet_kern_clocksource.c\
	uinet_kern_condvar.c	\
	uinet_kern_conf.c	\
	uinet_kern_environment.c\
	uinet_kern_intr.c	\
	uinet_kern_jail.c	\
	uinet_kern_kthread.c	\
	uinet_kern_lock.c	\
	uinet_kern_malloc.c	\
	uinet_kern_mib.c	\
	uinet_kern_mutex.c	\
	uinet_kern_priv.c	\
	uinet_kern_proc.c	\
	uinet_kern_prot.c	\
	uinet_kern_racct.c	\
	uinet_kern_resource.c	\
	uinet_kern_rmlock.c	\
	uinet_kern_rwlock.c	\
	uinet_kern_sig.c	\
	uinet_kern_sx.c		\
	uinet_kern_synch.c	\
	uinet_kern_time.c	\
	uinet_kern_timeout.c	\
	uinet_machdep.c		\
	uinet_dev_random.c	\
	uinet_sched.c		\
	uinet_subr_bus.c	\
	uinet_subr_pcpu.c	\
	uinet_subr_prf.c	\
	uinet_subr_rtc.c	\
	uinet_subr_smp.c	\
	uinet_subr_uio.c	\
	uinet_support.c		\
	uinet_tty.c		\
	uinet_uipc_shm.c	\
	uinet_uma_int.c		\
	uinet_vfs_bio.c		\
	uinet_vfs_mountroot.c	\
	uinet_vfs_ops.c		\
	uinet_vfs_subr.c	\
	uinet_vfs_syscalls.c	\
	uinet_vm_contig.c	\
	uinet_vm_glue.c		\
	uinet_vm_kern.c		\
	uinet_vm_meter.c	\
	uinet_vm_object.c

ifneq (${HOST_OS},Darwin)
UINET_SRCS+= uinet_if_netmap.c
endif


UINET_HOST_SRCS+=		\
	uinet_api_errno.c	\
	uinet_arc4random.c	\
	uinet_host_interface.c  \
	uinet_kern_shutdown.c

ifneq (${HOST_OS},Darwin)
UINET_HOST_SRCS+= uinet_if_netmap_host.c
endif


CRYPTO_SRCS+=			\
	sha1.c


KERN_SRCS+=			\
	kern_descrip.c		\
	kern_event.c		\
	kern_fail.c		\
	kern_khelp.c		\
	kern_hhook.c		\
	kern_linker.c		\
	kern_mbuf.c		\
	kern_module.c		\
	kern_mtxpool.c		\
	kern_ntptime.c		\
	kern_osd.c		\
	kern_sysctl.c		\
	kern_tc.c		\
	link_elf.c		\
	md5c.c			\
	subr_eventhandler.c	\
	subr_hash.c		\
	subr_kobj.c		\
	subr_lock.c		\
	subr_module.c		\
	subr_param.c		\
	subr_pcpu.c		\
	subr_sbuf.c		\
	subr_taskqueue.c	\
	subr_unit.c		\
	sys_capability.c	\
	sys_generic.c		\
	sys_socket.c		\
	uipc_accf.c		\
	uipc_mbuf.c		\
	uipc_mbuf2.c		\
	uipc_domain.c		\
	uipc_sockbuf.c		\
	uipc_socket.c


KERN_MHEADERS+=		\
	bus_if.m	\
	device_if.m	\
	linker_if.m


KERN_MSRCS+=		\
	linker_if.m


LIBKERN_SRCS+=		\
	bcd.c		\
	inet_ntoa.c


MACHINE_SRCS+=		\
	in_cksum.c


NET_SRCS+=		\
	bpf.c		\
	if.c		\
	if_clone.c	\
	if_dead.c	\
	if_ethersubr.c	\
	if_loop.c	\
	if_llatbl.c	\
	if_promiscinet.c\
	netisr.c	\
	pfil.c		\
	radix.c		\
	raw_cb.c	\
	raw_usrreq.c	\
	route.c		\
	rtsock.c		


NETINET_SRCS+=		\
	ip_carp.c	\
	if_ether.c	\
	igmp.c		\
	in.c		\
	in_mcast.c	\
	in_pcb.c	\
	in_promisc.c	\
	in_proto.c	\
	in_rmx.c	\
	ip_encap.c	\
	ip_fastfwd.c	\
	ip_icmp.c	\
	ip_id.c		\
	ip_input.c	\
	ip_options.c	\
	ip_output.c	\
	raw_ip.c	\
	tcp_debug.c	\
	tcp_hostcache.c	\
	tcp_input.c	\
	tcp_lro.c	\
	tcp_offload.c	\
	tcp_output.c	\
	tcp_reass.c	\
	tcp_sack.c	\
	tcp_subr.c	\
	tcp_syncache.c	\
	tcp_timer.c	\
	tcp_timewait.c	\
	tcp_usrreq.c	\
	udp_usrreq.c	\
	cc.c		\
	cc_newreno.c


NETINET6_SRCS+=


VM_SRCS+=		\
	uma_core.c


MHEADERS= $(patsubst %.m,%.h,${KERN_MHEADERS})
MHEADERS+= vnode_if.h vnode_if_newproto.h vnode_if_typedef.h

MSRCS= $(patsubst %.m,%.c,${KERN_MSRCS})

SRCS=  ${UINET_SRCS} ${CRYPTO_SRCS} ${KERN_SRCS} ${LIBKERN_SRCS} ${MACHINE_SRCS}
SRCS+= ${MSRCS} ${NET_SRCS} ${NETINET_SRCS} ${NETINET6_SRCS} ${VM_SRCS}

HOST_SRCS = ${UINET_HOST_SRCS}

OBJS+= $(patsubst %.c,%.o,${SRCS})
HOST_OBJS+= $(patsubst %.c,%.o,${HOST_SRCS})

#
# The library is built by first incrementally linking all the object
# to resolve internal references.  Then, all symbols are made local.
# Then, only the symbols that are part of the UINET API are made
# externally available.
#
libuinet.a: machine_includes uinet_api.symlist ${MHEADERS} ${MSRCS} ${HOST_OBJS} ${OBJS}
ifeq (${HOST_OS},Darwin)
	sed 's/.*/_&/' < uinet_api.symlist > uinet_api.symlist.darwin
	${LD} -r -o $*.ro -exported_symbols_list uinet_api.symlist.darwin ${HOST_OBJS} ${OBJS}
	rm uinet_api.symlist.darwin
else
	${LD} -r -o $*.ro ${HOST_OBJS} ${OBJS}
	nm $*.ro  | grep -v ' U ' | cut -d ' ' -f 3 > $*_localize_list.tmp
	objcopy --localize-symbols=$*_localize_list.tmp $*.ro 
	rm $*_localize_list.tmp
	objcopy --globalize-symbols=uinet_api.symlist $*.ro 
endif
	rm -f $@
	ar -cqs $@ $*.ro
	rm -f $*.ro

${HOST_OBJS}: %.o: %.c
	${HOST_C}

${OBJS}: %.o: %.c ${IMACROS_FILE}
	${NORMAL_C}


.SUFFIXES: .m

.m.c:
	${AWK} -f $S/tools/makeobjops.awk $< -c

.m.h:
	${AWK} -f $S/tools/makeobjops.awk $< -h

.PHONY: clean
clean:
	rm -f libuinet.a
	rm -f ${MHEADERS} ${MSRCS} ${HOST_OBJS} ${OBJS} ${PROGRAM} ${IMACROS_FILE}
	rm -rf ${MACHINE_INCLUDES_ROOT}


.PHONY: machine_includes
machine_includes:
	@rm -rf ${MACHINE_INCLUDES_ROOT}
	@mkdir -p ${MACHINE_INCLUDES_ROOT}/machine
	@cp -r $S/${MACHINE_CPUARCH}/include/* ${MACHINE_INCLUDES_ROOT}/machine
	@if [ "${X86_INCLUDES}" != "0" ]; then 				\
		mkdir -p ${MACHINE_INCLUDES_ROOT}/x86;			\
		cp -r $S/x86/include/* ${MACHINE_INCLUDES_ROOT}/x86;	\
	fi



#
# Distilled from FreeBSD src/sys/conf/kern.post.mk
#
vnode_if.h vnode_if_newproto.h vnode_if_typedef.h: $S/tools/vnode_if.awk \
    $S/kern/vnode_if.src
vnode_if.h: vnode_if_newproto.h vnode_if_typedef.h
	${AWK} -f $S/tools/vnode_if.awk $S/kern/vnode_if.src -h
vnode_if_newproto.h:
	${AWK} -f $S/tools/vnode_if.awk $S/kern/vnode_if.src -p
vnode_if_typedef.h:
	${AWK} -f $S/tools/vnode_if.awk $S/kern/vnode_if.src -q


include ${TOPDIR}/network/uinet/mk/kern.mk

