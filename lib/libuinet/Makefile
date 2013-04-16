#
# Derived from FreeBSD auto-generated kernel Makefile and
# machine-specific Makefile templates
#

S=$(TOP_DIR)/network/uinet/sys

include ${TOP_DIR}/network/uinet/mk/kern.pre.mk

INCLUDES+= -I$S/machine/${MACHINE_CPUARCH}
INCLUDES+= -I./opt

ifneq ($(filter amd64 i386,${MACHINE_CPUARCH}),)
INCLUDES+= -I$S/machine/x86
endif

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


VPATH+= $S/netinet
VPATH+= $S/netinet/cc

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

KERN_SRCS=


SRCS= ${NETINET_SRCS} ${NETINET6_SRCS} ${KERN_SRCS}


OBJS+=  $(patsubst %.cc,%.o,$(patsubst %.c,%.o,${SRCS}))

libuinet.a: ${OBJS}
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

.c.o:
	${NORMAL_C}



include ${TOP_DIR}/network/uinet/mk/kern.mk

