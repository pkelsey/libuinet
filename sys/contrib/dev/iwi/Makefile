#	$FreeBSD: release/9.1.0/sys/contrib/dev/iwi/Makefile 191945 2009-05-09 18:54:18Z sam $

FW_VERSION=3.1
ALL=	ipw2200-bss.fw.uu ipw2200-ibss.fw.uu ipw2200-sniffer.fw.uu

all:	${ALL}

ipw2200-bss.fw.uu: ipw2200-bss.fw LICENSE
	(cat LICENSE; \
	 echo '#define IWI_FW_VERSION' ${FW_VERSION}; \
	 uuencode ipw2200-bss.fw ipw2200-bss.fw) > ${.TARGET}

ipw2200-ibss.fw.uu: ipw2200-ibss.fw LICENSE
	(cat LICENSE; \
	 echo '#define IWI_FW_VERSION ' ${FW_VERSION}; \
	 uuencode ipw2200-ibss.fw ipw2200-ibss.fw) > ${.TARGET}

ipw2200-sniffer.fw.uu: ipw2200-sniffer.fw LICENSE
	(cat LICENSE; \
	 echo '#define IWI_FW_VERSION ' ${FW_VERSION}; \
	 uuencode ipw2200-sniffer.fw ipw2200-sniffer.fw) > ${.TARGET}

clean:
	rm -f ${ALL}
