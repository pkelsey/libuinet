/*
 * Copyright (c) 2015 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(__linux__)
/*
 * To expose required facilities in net/if.h.
 */
#define _GNU_SOURCE
#endif /* __linux__ */

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include "uinet_host_interface.h"
#include "uinet_if_pcap_host.h"


struct if_pcap_dumper {
	pcap_t *p;
	pcap_dumper_t *d;
	uint64_t flowid;
};

struct if_pcap_host_context {
	pcap_t *rx_p;
	int rx_isfile;
	pcap_t *tx_p;
	int tx_isfile;
	unsigned int tx_snaplen;
	unsigned int tx_file_per_flow;
	unsigned int tx_dirbits;
	uint32_t tx_epoch_no;
	uint32_t tx_instance_index;
	struct if_pcap_dumper tx_single_dumper;
	struct if_pcap_dumper *tx_dumper_hash;
	unsigned int tx_dumper_hash_mask;
	const char *rx_ifname;
	const char *tx_ifname;
	uint64_t last_packet_delivery;
	uint64_t last_packet_timestamp;		
#define PATH_BUFFER_SIZE 1024
	char path_buffer[PATH_BUFFER_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
};

static void if_pcap_destroy_dumper(struct if_pcap_host_context *ctx, struct if_pcap_dumper *d);


static pcap_t *
if_pcap_configure_live_interface(const char *ifname, pcap_direction_t direction,
				 unsigned int isnonblock, int *fd, char *errbuf)
{
	pcap_t *new_p;
	int dlt;
	
	new_p = pcap_create(ifname, errbuf);
	if (NULL == new_p)
		goto fail;

	if (-1 == pcap_setdirection(new_p, direction)) {
		printf("Could not restrict pcap capture to input on %s\n", ifname);
		goto fail;
	}

	pcap_set_timeout(new_p, 1);
	pcap_set_snaplen(new_p, 65535);
	pcap_set_promisc(new_p, 1);
	if (isnonblock)
		if (-1 == pcap_setnonblock(new_p, 1, errbuf)) {
			printf("Could not set non-blocking mode on %s\n", ifname);
			goto fail;
		}
	if (fd)
		if (-1 == (*fd = pcap_get_selectable_fd(new_p))) {
			printf("Could not get selectable fd for %s\n", ifname);
			goto fail;
		}

	switch (pcap_activate(new_p)) {
	case 0:
		break;
	case PCAP_WARNING_PROMISC_NOTSUP:
		printf("Promiscuous mode not supported on %s: %s\n", ifname, pcap_geterr(new_p));
		break;
	case PCAP_WARNING:
		printf("Warning while activating pcap capture on %s: %s\n", ifname, pcap_geterr(new_p));
		break;
	case PCAP_ERROR_NO_SUCH_DEVICE:
	case PCAP_ERROR_PERM_DENIED:
		printf("Error activating pcap capture on %s: %s\n", ifname, pcap_geterr(new_p));
		/* FALLTHOUGH */
	default:
		goto fail;
		break;
	}

	dlt = pcap_datalink(new_p);
	if (DLT_EN10MB != dlt) {
		printf("Data link type on %s is %d, only %d supported\n", ifname, dlt, DLT_EN10MB);
		goto fail;
	}

	return (new_p);

fail:
	if (new_p)
		pcap_close(new_p);
	return (NULL);
}


static int
if_pcap_make_dir_tree(struct if_pcap_host_context *ctx, const char *root, unsigned int bits_per_dir)
{
	unsigned int num_dirs;
	unsigned int hex_digits;
	int dir_name_begin;
	unsigned int i;
	int error;

	num_dirs = 1 << bits_per_dir;
	hex_digits = (bits_per_dir + 3) / 4;
	
	dir_name_begin = snprintf(ctx->path_buffer, PATH_BUFFER_SIZE, "%s/", root);
	if ((dir_name_begin < 0) ||
	    (dir_name_begin >= PATH_BUFFER_SIZE) ||
	    ((PATH_BUFFER_SIZE - dir_name_begin) <= hex_digits)) {
		return (1);
	}

	printf("Making %u directories in %s\n", num_dirs, root);
	for (i = 0; i < num_dirs; i++) {
		snprintf(&ctx->path_buffer[dir_name_begin], PATH_BUFFER_SIZE - dir_name_begin, "%0*x", hex_digits, i);
		error = uhi_mkdir(ctx->path_buffer, UHI_S_IRWXU | UHI_S_IRWXG | UHI_S_IRWXO);
		if (error && (error != EEXIST)) {
			return (1);
		}
	}

	return (0);
}


struct if_pcap_host_context *
if_pcap_create_handle(const char *rx_ifname, unsigned int rx_isfile, int *rx_fd, unsigned int rx_isnonblock,
		      const char *tx_ifname, unsigned int tx_isfile, unsigned int tx_file_snaplen,
		      unsigned int tx_file_per_flow, unsigned int tx_file_concurrent_flows, unsigned int tx_file_dirbits,
		      uint32_t tx_file_epoch_no, uint32_t tx_file_instance_index)
{
	struct if_pcap_host_context *ctx;
	int txisrx;
	unsigned int hashsize;

	ctx = calloc(1, sizeof(*ctx));
	if (NULL == ctx)
		goto fail;

	ctx->rx_isfile = rx_isfile;
	ctx->rx_ifname = rx_ifname;
	ctx->tx_isfile = tx_isfile;
	ctx->tx_file_per_flow = tx_file_per_flow;
	ctx->tx_snaplen = tx_file_snaplen;
	ctx->tx_ifname = tx_ifname;
	ctx->tx_dirbits = tx_file_dirbits;
	ctx->tx_epoch_no = tx_file_epoch_no;
	ctx->tx_instance_index = tx_file_instance_index;

	txisrx = !tx_isfile && !rx_isfile && rx_ifname && tx_ifname && (strcmp(tx_ifname, rx_ifname) == 0);

	if (ctx->tx_ifname) {
		if (!ctx->tx_isfile) {
			ctx->tx_p = if_pcap_configure_live_interface(tx_ifname,
								     txisrx ? PCAP_D_INOUT : PCAP_D_IN,
								     txisrx ? rx_isnonblock : 0,
								     (txisrx && rx_isnonblock) ? rx_fd : NULL,
								     ctx->errbuf);
			if (ctx->tx_p == NULL)
				goto fail;
		} else if (ctx->tx_file_per_flow) {
			if (if_pcap_make_dir_tree(ctx, ctx->tx_ifname, ctx->tx_dirbits))
				goto fail;

			for (hashsize = 1; hashsize <= tx_file_concurrent_flows; hashsize <<= 1)
				continue;
			hashsize >>= 1;

			if (hashsize == 0)
				hashsize = 1;
		
			ctx->tx_dumper_hash = calloc(hashsize, sizeof(*(ctx->tx_dumper_hash)));
			if (ctx->tx_dumper_hash == NULL)
				goto fail;
			ctx->tx_dumper_hash_mask = hashsize - 1;
		}
	}

	if (txisrx)
		ctx->rx_p = ctx->tx_p;
	else if (ctx->rx_ifname) {
		if (ctx->rx_isfile) {
			ctx->rx_p = pcap_open_offline(rx_ifname, ctx->errbuf);
			if (NULL == ctx->rx_p)
				goto fail;
		} else {
			ctx->rx_p = if_pcap_configure_live_interface(rx_ifname,
								     PCAP_D_OUT,
								     rx_isnonblock,
								     rx_isnonblock ? rx_fd : NULL,
								     ctx->errbuf);
			if (ctx->rx_p == NULL)
				goto fail;
		}
	}

	return (ctx);

fail:
	if (ctx) {
		if (ctx->tx_p)
			pcap_close(ctx->tx_p);
		if (ctx->rx_p && (ctx->rx_p != ctx->tx_p))
			pcap_close(ctx->rx_p);
		if (ctx->tx_dumper_hash)
			free(ctx->tx_dumper_hash);
		free(ctx);
	}

	return (NULL);
}


void
if_pcap_destroy_handle(struct if_pcap_host_context *ctx)
{
	unsigned int i;

	if (ctx->tx_ifname) {
		if (ctx->tx_isfile) {
			if (ctx->tx_file_per_flow) {
				for (i = 0; i <= ctx->tx_dumper_hash_mask; i++)
					if (ctx->tx_dumper_hash[i].d)
						if_pcap_destroy_dumper(ctx, &ctx->tx_dumper_hash[i]);
			} else if (ctx->tx_single_dumper.d)
				if_pcap_destroy_dumper(ctx, &ctx->tx_single_dumper);
		} else 
			pcap_close(ctx->tx_p);
	}
	if (ctx->rx_p && (ctx->rx_p != ctx->tx_p))
		pcap_close(ctx->rx_p);
	free(ctx->tx_dumper_hash);
	free(ctx);
}


#if !defined(__linux)
/*******************************************************************************
 * XXX awful hack to have pcap_dump_open_append() regardless of pcap library
 * version available
 */

#define HAVE_SNPRINTF
#include "pcap-int.h"

#define	SWAPLONG(y)							\
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))

extern int dlt_to_linktype(int dlt);

/*
 * Standard libpcap format.
 */
#define TCPDUMP_MAGIC		0xa1b2c3d4

/*
 * Alexey Kuznetzov's modified libpcap format.
 */
#define KUZNETZOV_TCPDUMP_MAGIC	0xa1b2cd34

/*
 * Reserved for Francisco Mesquita <francisco.mesquita@radiomovel.pt>
 * for another modified format.
 */
#define FMESQUITA_TCPDUMP_MAGIC	0xa1b234cd

/*
 * Navtel Communcations' format, with nanosecond timestamps,
 * as per a request from Dumas Hwang <dumas.hwang@navtelcom.com>.
 */
#define NAVTEL_TCPDUMP_MAGIC	0xa12b3c4d

/*
 * Normal libpcap format, except for seconds/nanoseconds timestamps,
 * as per a request by Ulf Lamping <ulf.lamping@web.de>
 */
#define NSEC_TCPDUMP_MAGIC	0xa1b23c4d

static int
sf_write_header(pcap_t *p, FILE *fp, int linktype, int thiszone, int snaplen)
{
	struct pcap_file_header hdr;

#ifdef PCAP_TSTAMP_PRECISION_NANO
	hdr.magic = p->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
#else
	hdr.magic = TCPDUMP_MAGIC;
#endif
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;

	hdr.thiszone = thiszone;
	hdr.snaplen = snaplen;
	hdr.sigfigs = 0;
	hdr.linktype = linktype;

	if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
		return (-1);

	return (0);
}

static pcap_dumper_t *
pcap_setup_dump(pcap_t *p, int linktype, FILE *f, const char *fname)
{

#if defined(_WIN32) || defined(MSDOS)
	/*
	 * If we're writing to the standard output, put it in binary
	 * mode, as savefiles are binary files.
	 *
	 * Otherwise, we turn off buffering.
	 * XXX - why?  And why not on the standard output?
	 */
	if (f == stdout)
		SET_BINMODE(f);
	else
		setbuf(f, NULL);
#endif
	if (sf_write_header(p, f, linktype, p->tzoff, p->snapshot) == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Can't write to %s: %s",
		    fname, pcap_strerror(errno));
		if (f != stdout)
			(void)fclose(f);
		return (NULL);
	}
	return ((pcap_dumper_t *)f);
}
#endif /* !defined(__linux) */

static pcap_dumper_t *
pcap_dump_open_append(pcap_t *p, const char *fname)
{
#if defined(__linux)
	printf("Warning: pcap file append mode not available, overwrite will be used instead");
	return NULL;
#else
	FILE *f;
	int linktype;
	size_t amt_read;
	struct pcap_file_header ph;

	linktype = dlt_to_linktype(p->linktype);
	if (linktype == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: link-layer type %d isn't supported in savefiles",
		    fname, linktype);
		return (NULL);
	}
	if (fname[0] == '-' && fname[1] == '\0')
		return (pcap_setup_dump(p, linktype, stdout, "standard output"));

#if !defined(_WIN32) && !defined(MSDOS)
	f = fopen(fname, "r+");
#else
	f = fopen(fname, "rb+");
#endif
	if (f == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s: %s",
		    fname, pcap_strerror(errno));
		return (NULL);
	}

	/*
	 * Try to read a pcap header.
	 */
	amt_read = fread(&ph, 1, sizeof (ph), f);
	if (amt_read != sizeof (ph)) {
		if (ferror(f)) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s: %s",
			    fname, pcap_strerror(errno));
			fclose(f);
			return (NULL);
		} else if (feof(f) && amt_read > 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: truncated pcap file header", fname);
			fclose(f);
			return (NULL);
		}
	}

#if defined(_WIN32) || defined(MSDOS)
	/*
	 * We turn off buffering.
	 * XXX - why?  And why not on the standard output?
	 */
	setbuf(f, NULL);
#endif

	/*
	 * If a header is already present and:
	 *
	 *	it's not for a pcap file of the appropriate resolution
	 *	and the right byte order for this machine;
	 *
	 *	the link-layer header types don't match;
	 *
	 *	the snapshot lengths don't match;
	 *
	 * return an error.
	 */
	if (amt_read > 0) {
		/*
		 * A header is already present.
		 * Do the checks.
		 */
		switch (ph.magic) {

		case TCPDUMP_MAGIC:
#ifdef PCAP_TSTAMP_PRECISION_NANO
			if (p->opt.tstamp_precision != PCAP_TSTAMP_PRECISION_MICRO) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "%s: different time stamp precision, cannot append to file", fname);
				fclose(f);
				return (NULL);
			}
#endif
			break;

#ifdef PCAP_TSTAMP_PRECISION_NANO
		case NSEC_TCPDUMP_MAGIC:
			if (p->opt.tstamp_precision != PCAP_TSTAMP_PRECISION_NANO) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "%s: different time stamp precision, cannot append to file", fname);
				fclose(f);
				return (NULL);
			}
			break;
#endif
			
		case SWAPLONG(TCPDUMP_MAGIC):
		case SWAPLONG(NSEC_TCPDUMP_MAGIC):
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: different byte order, cannot append to file", fname);
			fclose(f);
			return (NULL);

		case KUZNETZOV_TCPDUMP_MAGIC:
		case SWAPLONG(KUZNETZOV_TCPDUMP_MAGIC):
		case NAVTEL_TCPDUMP_MAGIC:
		case SWAPLONG(NAVTEL_TCPDUMP_MAGIC):
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: not a pcap file to which we can append", fname);
			fclose(f);
			return (NULL);

		default:
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: not a pcap file", fname);
			fclose(f);
			return (NULL);
		}

		/*
		 * Good version?
		 */
		if (ph.version_major != PCAP_VERSION_MAJOR ||
		    ph.version_minor != PCAP_VERSION_MINOR) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: version is %u.%u, cannot append to file", fname,
			    ph.version_major, ph.version_minor);
			fclose(f);
			return (NULL);
		}
		if (linktype != ph.linktype) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: different linktype, cannot append to file", fname);
			fclose(f);
			return (NULL);
		}
		if (p->snapshot != ph.snaplen) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: different snaplen, cannot append to file", fname);
			fclose(f);
			return (NULL);
		}
	} else {
		/*
		 * A header isn't present; attempt to write it.
		 */
		if (sf_write_header(p, f, linktype, p->tzoff, p->snapshot) == -1) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Can't write to %s: %s",
			    fname, pcap_strerror(errno));
			(void)fclose(f);
			return (NULL);
		}
	}

	/*
	 * Start writing at the end of the file.
	 */
	if (fseek(f, 0, SEEK_END) == -1) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Can't seek to end of %s: %s",
		    fname, pcap_strerror(errno));
		(void)fclose(f);
		return (NULL);
	}
	return ((pcap_dumper_t *)f);
#endif
}

/*
 * XXX end awful pcap_dump_open_append() hack
 ******************************************************************************/


static void
if_pcap_create_dumper(struct if_pcap_host_context *ctx, struct if_pcap_dumper *d, uint64_t flowid)
{
	pcap_t *new_p;
	pcap_dumper_t *new_d;
	const char *name;
	uint32_t hex_digits, dirno;
	
	new_p = pcap_open_dead(DLT_EN10MB, ctx->tx_snaplen);
	if (new_p == NULL)
		return;

	if (ctx->tx_file_per_flow) {
		dirno = flowid & ((1 << ctx->tx_dirbits) - 1);
		hex_digits = (ctx->tx_dirbits + 3) / 4;
		snprintf(ctx->path_buffer, sizeof(ctx->path_buffer), "%s/%0*x/%08x-%08x-%016llx.pcap",
			 ctx->tx_ifname, hex_digits, dirno,
			 ctx->tx_epoch_no, ctx->tx_instance_index, (unsigned long long)flowid);
		name = ctx->path_buffer;
	} else
		name = ctx->tx_ifname;

	/* Add to existing file, or create a new one if none. */
	new_d = pcap_dump_open_append(new_p, name);
	if (new_d == NULL)
		new_d = pcap_dump_open(new_p, name);

	if (new_d == NULL) {
		pcap_close(new_p);
		return;
	}

	d->p = new_p;
	d->d = new_d;
	d->flowid = flowid;
}


static void
if_pcap_destroy_dumper(struct if_pcap_host_context *ctx, struct if_pcap_dumper *d)
{
	pcap_dump_close(d->d);
	pcap_close(d->p);
	memset(d, 0, sizeof(*d));
}


/*
 * In file-per-flow mode, a hash is kept of open dump files keyed by flowid.
 * Dump files are closed, and the hash entry replaced, on collision.
 */
static pcap_dumper_t *
if_pcap_get_dumper(struct if_pcap_host_context *ctx, uint64_t flowid, unsigned int create)
{
	struct if_pcap_dumper *d;
	struct if_pcap_dumper new_d;
	
	if (ctx->tx_file_per_flow) {
		d = &ctx->tx_dumper_hash[flowid & ctx->tx_dumper_hash_mask];
		if (d->d != NULL) {
			if (d->flowid != flowid) {
				if (!create)
					return (NULL);
				new_d.d = NULL;
				if_pcap_create_dumper(ctx, &new_d, flowid);
				if (new_d.d == NULL)
					return (NULL);
				if_pcap_destroy_dumper(ctx, d);
				*d = new_d;
			} /* else d is the dumper we want */
		} else if (create)
			if_pcap_create_dumper(ctx, d, flowid);
		else
			return (NULL);
		return (d->d);
	} else {
		if (ctx->tx_single_dumper.d == NULL)
			if_pcap_create_dumper(ctx, &ctx->tx_single_dumper, 0);
		return (ctx->tx_single_dumper.d);
	} 
}


int
if_pcap_sendpacket(struct if_pcap_host_context *ctx, const uint8_t *buf, unsigned int size,
		   uint64_t flowid, uint64_t ts_nsec)
{
	pcap_dumper_t *d;
	struct pcap_pkthdr h;
	
	if (ctx->tx_isfile) {
		d = if_pcap_get_dumper(ctx, flowid, 1);
		if (d == NULL)
			return (-1);

		h.ts.tv_sec = ts_nsec / 1000000000;
		h.ts.tv_usec = (ts_nsec % 1000000000) / 1000;
		h.caplen = (size > ctx->tx_snaplen) ? ctx->tx_snaplen : size;
		h.len = size;
		pcap_dump((unsigned char *)d, &h, buf);
		return (0);
	} else
		return pcap_sendpacket(ctx->tx_p, buf, size);
}


void
if_pcap_flushflow(struct if_pcap_host_context *ctx, uint64_t flowid)
{
	pcap_dumper_t *d;

	d = if_pcap_get_dumper(ctx, flowid, 1);
	if (d != NULL)
		pcap_dump_flush(d);
}


int
if_pcap_getpacket(struct if_pcap_host_context *ctx, uint64_t now,
		  uint32_t *buffer, uint16_t max_length, uint16_t *length,
		  uint64_t *timestamp, uint64_t *wait_ns)
{
	uint64_t hdr_timestamp;
	uint64_t time_since_last_delivery;
	uint64_t time_since_last_capture;		
	struct pcap_pkthdr *hdr;
	const uint8_t *data;
	
	switch (pcap_next_ex(ctx->rx_p, &hdr, &data)) {
	default:
	case -2: /* EOF when reading from file */
	case -1: /* error */
		return (-1);
	case 0: /* timeout or non-blocking and none available */
		return (0);
	case 1: /* success */
		hdr_timestamp = (uint64_t)hdr->ts.tv_sec * 1000000000 + (uint64_t)hdr->ts.tv_usec * 1000;
		if (ctx->rx_isfile) {
			*length = (hdr->caplen <= max_length) ? hdr->caplen : max_length;
			memcpy(buffer, data, *length);
			
			time_since_last_delivery = now - ctx->last_packet_delivery;
			time_since_last_capture = hdr_timestamp - ctx->last_packet_timestamp;

			if ((ctx->last_packet_delivery == 0) ||
			    (time_since_last_delivery >= time_since_last_capture))
				*wait_ns = 0;
			else
				*wait_ns = time_since_last_capture - time_since_last_delivery;
		
			ctx->last_packet_delivery = now;
			ctx->last_packet_timestamp = hdr_timestamp;
		} else {
			*wait_ns = 0;
		}
		*timestamp = hdr_timestamp;
		return (1);	
	}
}




