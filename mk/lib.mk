
ifdef DEBUG_FLAGS
CFLAGS+=${DEBUG_FLAGS}
CXXFLAGS+=${DEBUG_FLAGS}
endif

ifndef LIB
$(error  LIB must be defined.)
endif

ifndef SRCS
SRCS=	${LIB}.c
endif

OBJS+= $(patsubst %.cc,%.o,$(patsubst %.c,%.o,${SRCS}))


#
# Include Makefile.inc from each UINET library that is being used and
# set up the compiler and linker options for finding and linking to
# each one.
#
UINET_LIB_PATHS:= $(foreach lib,${UINET_LIBS},${TOPDIR}/lib/lib$(lib))
UINET_CFLAGS:= $(foreach lib,${UINET_LIBS}, -I${TOPDIR}/lib/lib$(lib)$(if $(wildcard ${TOPDIR}/lib/lib$(lib)/api_include),/api_include))

CFLAGS+= ${UINET_CFLAGS}

LIBBASENAME=lib${LIB}


${LIBBASENAME}.a: ${OBJS}
	rm -f $@
	ar -cqs $@ ${OBJS}

${OBJS}: %.o: %.c
	${CC} -c ${CFLAGS} $<

clean:
	@rm -f ${LIBBASENAME}.a ${OBJS}

all: ${LIBBASENAME}.a

install:
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/lib
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/include/${LIBBASENAME}/
	${UINET_INSTALL_BIN} ${LIBBASENAME}.a ${UINET_DESTDIR}/lib
ifdef DIST_INCLUDES
	${UINET_INSTALL_INC} ${DIST_INCLUDES} ${UINET_DESTDIR}/include/${LIBBASENAME}/
endif

config:
