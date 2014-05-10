CPPFLAGS+=-I${TOPDIR}/network/uinet/lib/libuinet/api_include
CPPFLAGS+=-DHAVE_UINET=1

LDADD+=         -L${TOPDIR}/network/uinet/lib/libuinet
LDADD+=		-luinet
LDADD+=		-lpcap
ifeq "${OSNAME}" "Linux"
LDADD+=		-lcrypto
else
LDADD+=		-lssl
endif
