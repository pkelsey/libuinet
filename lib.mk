CPPFLAGS+=-I${TOPDIR}/lib/libuinet/api_include
CPPFLAGS+=-DHAVE_UINET=1

LDADD+=         -L${TOPDIR}/lib/libuinet
LDADD+=		-luinet
ifeq "${OSNAME}" "Linux"
LDADD+=		-lcrypto
else
LDADD+=		-lssl
endif
