#
# Derived from FreeBSD auto-generated kernel Makefile and
# machine-specific Makefile templates
#

S=$(TOP_DIR)/network/uinet/sys

include ${TOP_DIR}/network/uinet/mk/kern.pre.mk

KERNPREINCLUDES:= ${INCLUDES}
INCLUDES= -I${TOP_DIR}/network/uinet/lib/libuinet/include ${KERNPREINCLUDES}


INCLUDES+= -I$S/machine/${MACHINE_CPUARCH}
INCLUDES+= -I./opt

ifneq (${COMPILER_TYPE},clang)
STDINC_PATH:= $(patsubst %,-I%,$(shell `${CC} -print-prog-name=cc1` -v < /dev/null 2>&1 | sed '/\// !d'))
else
STDINC_PATH:= $(patsubst %,-I%,$(shell ${CC} -E -Xpreprocessor -v - < /dev/null 2>&1 | sed '/\// !d'))
endif


ifneq ($(filter amd64 i386,${MACHINE_CPUARCH}),)
INCLUDES+= -I$S/machine/x86
endif

INCLUDES+= ${STDINC_PATH}

#
# Distilled from FreeBSD src/sys/conf/Makefile.amd64
#
ifeq (${MACHINE_CPUARCH},amd64)
ifneq (($or ${DDB_ENABLED}, ${DTR_ENABLED}, ${HWPMC_ENABLED}),)
CFLAGS+=	-fno-omit-frame-pointer
endif
endif

#
# Distilled from FreeBSD src/sys/conf/Makefile.arm
#
ifeq (${MACHINE_CPUARCH},arm)

ifneq (${COMPILER_TYPE},clang)
CFLAGS += -mno-thumb-interwork
endif

ifeq (${DDB_ENABLED},)
ifndef WITH_ARM_EABI
ifneq (${COMPILER_TYPE},clang)
CFLAGS += -mno-apcs-frame
endif
endif
else ifdef WITH_ARM_EABI
CFLAGS += -funwind-tables
ifeq (${COMPILER_TYPE},clang)
# clang requires us to tell it to emit assembly with unwind information
CFLAGS += -mllvm -arm-enable-ehabi
endif
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

VPATH+= $S/machine/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}
VPATH+= $S/kern
VPATH+= $S/net
VPATH+= $S/netinet
VPATH+= $S/netinet/cc

UINET_SRCS+=			\
	uinet_init_main.c	\
	uinet_kern_clock.c	\
	uinet_kern_lock.c	\
	uinet_kern_malloc.c	\
	uinet_kern_mutex.c	\
	uinet_kern_rmlock.c	\
	uinet_kern_rwlock.c	\
	uinet_kern_shutdown.c	\
	uinet_kern_sx.c		\
	uinet_kern_synch.c	\
	uinet_kern_timeout.c	\
	uinet_main.c		\
	uinet_support.c

# want vnode_if - do we really need to know about vnodes anywhere?
#	kern_linker.c		\
#	link_elf.c		\
#	link_elf_obj.c		\
#	sys_generic.c		\
#	uipc_syscalls.c

# not sure if we need yet
#	kern_event.c		\



KERN_SRCS+=			\
	kern_descrip.c		\
	kern_environment.c	\
	kern_fail.c		\
	kern_khelp.c		\
	kern_hhook.c		\
	kern_mbuf.c		\
	kern_module.c		\
	kern_mtxpool.c		\
	kern_ntptime.c		\
	kern_osd.c		\
	kern_sysctl.c		\
	kern_tc.c		\
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
	sys_socket.c		\
	uipc_accf.c		\
	uipc_mbuf.c		\
	uipc_mbuf2.c		\
	uipc_domain.c		\
	uipc_sockbuf.c		\
	uipc_socket.c


KERN_MFILES+=		\
	bus_if.m	\
	device_if.m	\
	vnode_if.m

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


NETINET6_SRCS=

MFILES= ${KERN_MFILES}

MHEADERS= $(patsubst %.m,%.h,${MFILES})

SRCS= ${UINET_SRCS} ${KERN_SRCS} ${MACHINE_SRCS} ${NET_SRCS} ${NETINET_SRCS} ${NETINET6_SRCS}

OBJS+= $(patsubst %.cc,%.o,$(patsubst %.c,%.o,${SRCS}))

PROGRAM=uinet_test

LDADD+= -lpthread

${PROGRAM}: ${MHEADERS} ${OBJS}
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

.c.o:
	${NORMAL_C}

.m.h:
	${AWK} -f $S/tools/makeobjops.awk $< -h

clean:
	rm -f ${PROGRAM} ${OBJS} ${MHEADERS}


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


include ${TOP_DIR}/network/uinet/mk/kern.mk

