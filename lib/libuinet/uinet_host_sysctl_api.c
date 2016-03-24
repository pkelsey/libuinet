/*
 * Copyright (c) 2014 Adrian Chadd.  All rights reserved.
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

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "uinet_api.h"
#include "uinet_nv.h"
#include "uinet_host_sysctl_api.h"
#include "uinet_host_sysctl_api_priv.h"

//#define	UINET_SYSCTL_DEBUG

#ifdef	UINET_SYSCTL_DEBUG
#define	UINET_SYSCTL_DPRINTF(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define	UINET_SYSCTL_DPRINTF(fmt, ...)
#endif

struct u_sysctl_state_t {
	nvlist_t *nvl_resp;

	int ns;
	char *wbuf;
	size_t wbuf_len;
	size_t sbuf_len;
	const char *sbuf;
	int error;
	size_t rval;
	char *oldp;

	/*
	 * This is the posix shm state
	 */
	int shm_fd;
	char *shm_mem;
	size_t shm_len;
	const char *shm_path;
	int retval;
};

static void
passive_sysctl_state_init(struct u_sysctl_state_t *us, int ns)
{
	bzero(us, sizeof(*us));

	us->shm_fd = -1;
	us->ns = ns;
}

static void
passive_sysctl_state_clean(struct u_sysctl_state_t *us)
{

	if (us->wbuf != NULL)
		free(us->wbuf);
	if (us->shm_mem != NULL)
		munmap(us->shm_mem, us->shm_len);
	if (us->shm_fd != -1)
		close(us->shm_fd);
	if (us->nvl_resp != NULL)
		nvlist_destroy(us->nvl_resp);
}

/*
 * Return 1 if things are ok, 0 if somehow things failed.
 */
static int
passive_sysctl_handle_req(struct u_sysctl_state_t *us, nvlist_t *nvl)
{

	/*
	 * If the shm stuff is provided, grab it.
	 *
	 * XXX Validate that it is indeed a valid path somehow?
	 */
	if (nvlist_exists_string(nvl, "sysctl_respbuf_shm_path")) {
		/* XXX strdup, then free as appropriate */
		us->shm_path = nvlist_get_string(nvl, "sysctl_respbuf_shm_path");
		if (! nvlist_exists_number(nvl, "sysctl_respbuf_shm_len")) {
			UINET_SYSCTL_DPRINTF("%s: shm_path provided but not shm_len\n",
			    __func__);
			us->retval = 0;
			return (0);
		}

		/*
		 * If we have an shm_path, then we absolutely require
		 * a respbuf_len field.
		 */
		if (! nvlist_exists_number(nvl, "sysctl_respbuf_len")) {
			UINET_SYSCTL_DPRINTF("%s: shm_path provided but no shm_respbuf_len!\n",
			    __func__);
			us->retval = 0;
			return (0);
		}

		us->shm_len = nvlist_get_number(nvl, "sysctl_respbuf_shm_len");

		us->shm_fd = shm_open(us->shm_path, O_RDWR, 0644);
		if (us->shm_fd < 0) {
#ifdef	UINET_SYSCTL_DEBUG
			warn("%s: shm_open (%s)", __func__, us->shm_path);
#endif
			us->retval = 0;
			return (0);
		}

		/* mmap it */
		us->shm_mem = mmap(NULL, us->shm_len, PROT_READ, 0, us->shm_fd, 0);
		if (us->shm_mem == NULL) {
#ifdef	UINET_SYSCTL_DEBUG
			warn("%s: mmap (%s)", __func__, us->shm_path);
#endif
			us->retval = 0;
			return (0);
		}
	}

	/*
	 * We may not have a response buffer length provided.
	 * This is done when writing a sysctl value.
	 */
	if (nvlist_exists_number(nvl, "sysctl_respbuf_len")) {

		/*
		 * Only validate length here if we don't have a shm.
		 * We enforce a maximum size requirement on non-SHM
		 * requests.
		 */
		if (us->shm_mem == NULL && nvlist_get_number(nvl,
		    "sysctl_respbuf_len") > U_SYSCTL_MAX_REQ_BUF_LEN) {
			UINET_SYSCTL_DPRINTF("%s: fd %d: sysctl_respbuf_len is "
			    "too big! (%llu)\n",
			    __func__,
			    us->ns,
			    (unsigned long long) nvlist_get_number(nvl,
			      "sysctl_respbuf_len"));
			us->retval = 0;
			return (0);
		}
		us->wbuf_len = nvlist_get_number(nvl, "sysctl_respbuf_len");
	} else {
		us->wbuf_len = 0;
	}

	/*
	 * If we have a shm, ensure respbuf_len <= shm_len.
	 */
	if (us->shm_mem != NULL) {
		if (us->wbuf_len > us->shm_len) {
			UINET_SYSCTL_DPRINTF("%s: fd %d: respbuf_len %lld > shm_len %lld\n",
			    __func__,
			    us->ns,
			    (long long) us->wbuf_len,
			    (long long) us->shm_len);
			us->retval = 0;
			return (0);
		}
	}

	/*
	 * If we have a shm_buf, pass that in.
	 *
	 * Otherwise, if wbuf_len is 0, pass in a NULL wbuf.
	 *
	 * Otherwise, allocate a wbuf.
	 */

	/* If wbuf_len is 0, then pass in a NULL wbuf */
	if (us->shm_mem != NULL) {
		us->wbuf = NULL;
		us->oldp = us->shm_mem;
	}
	if (us->wbuf_len == 0) {
		us->wbuf = NULL;
		us->oldp = NULL;
	} else {
		us->wbuf = calloc(1, us->wbuf_len);
		if (us->wbuf == NULL) {
			UINET_SYSCTL_DPRINTF("%s: fd %d: malloc failed\n",
			    __func__,
			    us->ns);
			us->retval = 0;
			return (0);
		}
		us->oldp = us->wbuf;
	}

	/* sysctl_reqbuf */
	if (nvlist_exists_binary(nvl, "sysctl_reqbuf")) {
		us->sbuf = nvlist_get_binary(nvl, "sysctl_reqbuf", &us->sbuf_len);
	} else {
		us->sbuf = NULL;
		us->sbuf_len = 0;
	}

	return (1);
}


static void
passive_sysctl_handle_resp(struct u_sysctl_state_t *us)
{

	/*
	 * We only copy the data back if wbuf is not NULL.
	 *
	 * The undocumented size lookup in sysctl is done by
	 * doing a sysctl fetch on the given OID but with oldplen=0 and
	 * oldp=NULL, oldplen gets updated with the storage size.
	 */

	/*
	 * Validate the response back from uinet_sysctl()
	 * is within bounds for the response back to the
	 * client.
	 */
	if (us->wbuf != NULL && us->error == 0 && us->rval > us->wbuf_len) {
		UINET_SYSCTL_DPRINTF("%s: fd %d: rval (%llu) > wbuf_len (%llu)\n",
		    __func__,
		    us->ns,
		    (unsigned long long) us->rval,
		    (unsigned long long) us->wbuf_len);
		us->retval = 0;
		return;
	}

	/* Construct our response */
	us->nvl_resp = nvlist_create(0);
	if (us->nvl_resp == NULL) {
		fprintf(stderr, "%s: fd %d: nvlist_create failed\n", __func__, us->ns);
		us->retval = 0;
		return;
	}

	nvlist_add_number(us->nvl_resp, "sysctl_errno", us->error);

	/* wbuf is NULL if we have a shm response */
	if (us->error == 0 && us->wbuf != NULL) {
		nvlist_add_binary(us->nvl_resp, "sysctl_respbuf", us->wbuf, us->rval);
	}
	nvlist_add_number(us->nvl_resp, "sysctl_respbuf_len", us->rval);

	if (nvlist_send(us->ns, us->nvl_resp) < 0) {
		fprintf(stderr, "%s: fd %d: nvlist_send failed; errno=%d\n",
		    __func__,
		    us->ns,
		    errno);
		us->retval = 0;
		return;
	}

	/* Done! */
	us->retval = 1;
}

/*
 * Handle sysctl string type requests.
 *
 * Returns 1 if the connection should stay open; 0 if
 * not.
 */
static int
passive_sysctl_reqtype_str(int ns, nvlist_t *nvl, struct u_sysctl_state_t *us)
{
	const char *req_str;

	/* Setup! */
	passive_sysctl_state_init(us, ns);

	/* Parse initial bits */

	/*
	 * We absolutely require there to be a sysctl_str field.
	 * Ensure it's here.
	 */
	if (! nvlist_exists_string(nvl, "sysctl_str")) {
		UINET_SYSCTL_DPRINTF("%s: fd %d: missing sysctl_str\n",
		    __func__,
		    ns);
		us->retval = 0;
		goto finish;
	}
	req_str = nvlist_get_string(nvl, "sysctl_str");

	/* XXX enforce maximum string length */

	/* parse shared bits */
	if (! passive_sysctl_handle_req(us, nvl))
		goto finish;

	/* Issue sysctl */
	UINET_SYSCTL_DPRINTF("%s: fd %d: sysctl str=%s, oldp=%p, "
	    "oldplen=%d, newp=%p, newplen=%d\n",
	    __func__,
	    ns,
	    req_str,
	    us->wbuf,
	    (int) us->wbuf_len,
	    us->sbuf,
	    (int) us->sbuf_len);

	/*
	 * Pass in a NULL wbuf_len if wbuf is NULL.  sysctl writing
	 * passes in a NULL buffer and NULL oidlenp.
	 */
	us->error = uinet_sysctlbyname(uinet_instance_default(),
	    req_str,
	    us->oldp,
	    us->oldp == NULL ? NULL : &us->wbuf_len,
	    us->sbuf,
	    us->sbuf_len,
	    &us->rval,
	    0);

	UINET_SYSCTL_DPRINTF("%s: fd %d: sysctl error=%d, wbuf_len=%llu, "
	    "rval=%llu\n",
	    __func__,
	    ns,
	    (int) us->error,
	    (unsigned long long) us->wbuf_len,
	    (unsigned long long) us->rval);

	passive_sysctl_handle_resp(us);

finish:
	passive_sysctl_state_clean(us);
	return (us->retval);
}

/*
 * Handle sysctl oid type requests.
 *
 * Returns 1 if the connection should stay open; 0 if
 * not.
 *
 * XXX this is definitely not endian-clean.
 * I'm just passing in sysctl_oid as a binary array. Ew.
 */
static int
passive_sysctl_reqtype_oid(int ns, nvlist_t *nvl, struct u_sysctl_state_t *us)
{
	const int *req_oid;
	size_t req_oid_len;

	/* Setup! */
	passive_sysctl_state_init(us, ns);

	/* Parse initial bits */

	/*
	 * We absolutely require there to be a sysctl_oid field.
	 * Ensure it's here.
	 */
	if (! nvlist_exists_binary(nvl, "sysctl_oid")) {
		UINET_SYSCTL_DPRINTF("%s: fd %d: missing sysctl_oid\n",
		    __func__,
		    ns);
		us->retval = 0;
		goto finish;
	}
	req_oid = (const int *) nvlist_get_binary(nvl, "sysctl_oid",
	    &req_oid_len);
	if (req_oid_len % sizeof(int) != 0) {
		UINET_SYSCTL_DPRINTF("%s: fd %d: req_oid_len (%llu) "
		    "is not a multiple of %d\n",
		    __func__,
		    ns,
		    (unsigned long long) req_oid_len,
		    (int) sizeof(int));
		us->retval = 0;
		goto finish;
	}

	/* parse shared bits */
	if (! passive_sysctl_handle_req(us, nvl))
		goto finish;

	/* Issue sysctl */
	UINET_SYSCTL_DPRINTF("%s: fd %d: sysctl oid oidlen=%d oldp=%p, "
	    "oldplen=%d, newp=%p, newplen=%d\n",
	    __func__,
	    ns,
	    (int) (req_oid_len / sizeof(int)),
	    us->wbuf,
	    (int) us->wbuf_len,
	    us->sbuf,
	    (int) us->sbuf_len);

	/* XXX typecasting sbuf and req_oid sucks */
	/*
	 * Pass in a NULL wbuf_len if wbuf is NULL.  sysctl writing
	 * passes in a NULL buffer and NULL oidlenp.
	 */
	us->error = uinet_sysctl(uinet_instance_default(),
	    req_oid,
	    req_oid_len / sizeof(int),
	    us->oldp,
	    us->oldp == NULL ? NULL : &us->wbuf_len,
	    us->sbuf,
	    us->sbuf_len,
	    &us->rval,
	    0);

	UINET_SYSCTL_DPRINTF("%s: fd %d: sysctl error=%d, "
	    "wbuf_len=%llu, rval=%llu\n",
	    __func__,
	    ns,
	    (int) us->error,
	    (unsigned long long) us->wbuf_len,
	    (unsigned long long) us->rval);

	passive_sysctl_handle_resp(us);

finish:
	passive_sysctl_state_clean(us);
	return (us->retval);
}

void *
uinet_host_sysctl_listener_thread(void *arg)
{
	int s, r;
	struct sockaddr_un sun;
	struct uinet_host_sysctl_cfg *cfg = arg;
	char *path;

	path = "/tmp/sysctl.sock";
	if (cfg) {
		path = cfg->sysctl_sock_path;
	}
	uinet_initialize_thread("sysctl");

	(void) unlink(path);

	bzero(&sun, sizeof(sun));
	strcpy(sun.sun_path, path);
	sun.sun_family = AF_UNIX;

	printf("sysctl_listener: starting listener on %s\n", sun.sun_path);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		fprintf(stderr, "%s: socket failed: %d\n", __func__, errno);
		return NULL;
	}

	r = bind(s, (struct sockaddr *) &sun, sizeof(sun));
	if (r < 0) {
		fprintf(stderr, "%s: bind failed: %d\n", __func__, errno);
		return NULL;
	}

	r = listen(s, 10);
	if (r < 0) {
		fprintf(stderr, "%s: listen failed: %d\n", __func__, errno);
		return NULL;
	}

	/*
	 * Yes, I could make this threaded or non-blocking..
	 */
	for (;;) {
		struct sockaddr_un sun_n;
		socklen_t sl;
		nvlist_t *nvl;
		int ns;
		int ret;
		const char *type;

		ns = accept(s, (struct sockaddr *) &sun_n, &sl);
		if (ns < 0) {
			fprintf(stderr, "%s: accept failed: %d\n", __func__, errno);
			continue;
		}

		for (;;) {
			struct u_sysctl_state_t us;

			nvl = nvlist_recv(ns);
			if (nvl == NULL)
				break;

			if (! nvlist_exists_string(nvl, "type")) {
				fprintf(stderr, "%s: fd %d: no type; bailing\n",
				    __func__,
				    ns);
				break;
			}
			type = nvlist_get_string(nvl, "type");

			UINET_SYSCTL_DPRINTF("%s: fd %d: type=%s\n",
			    __func__,
			    ns,
			    type);

			/* Dispatch as appropriate */
			bzero(&us, sizeof(us));
			if (strncmp(type, "sysctl_str", 10) == 0) {
				ret = passive_sysctl_reqtype_str(ns, nvl, &us);
			} else if (strncmp(type, "sysctl_oid", 10) == 0) {
				ret = passive_sysctl_reqtype_oid(ns, nvl, &us);
			} else {
				fprintf(stderr, "%s: fd %d: unknown type=%s\n",
				    __func__,
				    ns,
				    nvlist_get_string(nvl, "type"));
				break;
			}

			/* Tidyup */
			nvlist_destroy(nvl);

			/* Ret == 0? Then we don't wait around */
			if (ret == 0)
				break;
		}

		/* Done; bail */
		close(ns);
	}

	return NULL;
}
