#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/endian.h>
#include <sys/param.h>	/* for round_page() */

#include <sys/mman.h>

#include "uinet_host_sysctl_api.h"
#include "uinet_nv.h"

/*
 * XXX TODO:
 *
 * + the sysctl shm stuff should be a transaction based thing
 * + the API should be modified so it returns the buffer, and then
 *   has a "finish" function that frees it if appropriate - that
 *   way for shm buffers we don't need to double allocate things.
 * + .. we shouldn't be doing all the mmap / munmap stuff - it
 *   will cause IPI shootdowns as the memory map in the libuinet
 *   using code has its memory map change.  I'll solve that
 *   later.
 */

static int
u_sysctl_do_sysctl(struct nvlist *nvl, int ns,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen)
{
	nvlist_t *nvl_resp = NULL;
	int retval = 0;
	int r_errno;
	const char *rbuf;
	size_t r_len;

	/* XXX Eventually this should be in a sysctl transaction struct */
	int shm_fd = -1;
	char *shm_mem = NULL;
	size_t shm_len = 0;
	char shm_path[128];

	/* Setup request and response buffer information */

	/*
	 * If the requested size is provided and it's greater than the
	 * maximum size allowed, we'll flip to using shm
	 */
	if (oldlenp != NULL && *oldlenp >= U_SYSCTL_MAX_REQ_BUF_LEN) {
		/* Construct a shm path */
		/* XXX should make this less guessable */
		snprintf(shm_path, 128, "/sysctl.%ld", (long) arc4random());

		/* Open it */
		shm_fd = shm_open(shm_path, O_CREAT | O_RDWR, 0640);
		if (shm_fd < 0) {
			warn("shm_open (%s)", shm_path);
			retval = -1;
			goto done;
		}

		/*
		 * Calculate a mmap size that's a multiple of
		 * the system page length.
		 */
		shm_len = round_page(*oldlenp);

		/* make it that big! */
		if (ftruncate(shm_fd, shm_len) < 0) {
			warn("ftruncate");
			goto done;
		}

		/* mmap it */
		shm_mem = mmap(NULL, shm_len, PROT_READ | PROT_WRITE,
		    0, shm_fd, 0);
		if (shm_mem == NULL) {
			warn("mmap");
			goto done;
		}

		/* add the shm path to the outbound request */
		nvlist_add_string(nvl, "sysctl_respbuf_shm_path", shm_path);
		nvlist_add_number(nvl, "sysctl_respbuf_shm_len", shm_len);
	}

	/*
	 * Writing a value may pass in a NULL oldlenp, so only conditionally
	 * send it.
	 */
	if (oldlenp != NULL)
		nvlist_add_number(nvl, "sysctl_respbuf_len", *oldlenp);

	if (newlen > 0) {
		nvlist_add_binary(nvl, "sysctl_reqbuf", newp, newlen);
	}

	/* Send command */
	if (nvlist_send(ns, nvl) < 0) {
		warn("nvlist_send");
		retval = -1;
		goto done;
	}

	/* Read response */
	nvl_resp = nvlist_recv(ns);
	if (nvl_resp == NULL) {
		warn("nvlist_recv");
		retval = -1;
		goto done;
	}

	if (! nvlist_exists_number(nvl_resp, "sysctl_errno")) {
		fprintf(stderr, "response: no errno?\n");
		goto done;
	}
	r_errno = (int) nvlist_get_number(nvl_resp, "sysctl_errno");

	/* XXX validate r_len versus oldlenp */
	if (nvlist_exists_binary(nvl_resp, "sysctl_respbuf")) {
		rbuf = nvlist_get_binary(nvl_resp, "sysctl_respbuf", &r_len);
		memcpy(oldp, rbuf, r_len);
	} else if (shm_mem != NULL) {
		memcpy(oldp, shm_mem, r_len);
		r_len = nvlist_get_number(nvl_resp, "sysctl_respbuf_shm_len");
	} else if (nvlist_exists_number(nvl_resp, "sysctl_respbuf_len")) {
		r_len = nvlist_get_number(nvl_resp, "sysctl_respbuf_len");
	} else {
		r_len = 0;
	}

	if (oldlenp != NULL)
		*oldlenp = r_len;

	if (r_errno == 0) {
		retval = 0;
	} else {
		retval = -1;
		errno = r_errno;
	}

done:
	if (shm_mem != NULL)
		munmap(shm_mem, shm_len);
	if (shm_fd != -1) {
		close(shm_fd);
		shm_unlink(shm_path);
	}
	if (nvl_resp)
		nvlist_destroy(nvl_resp);
	return (retval);
}

int
u_sysctlbyname(int ns,
    const char *name,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen)
{
	nvlist_t *nvl = NULL;
	int retval = 0;

	/* Create nvlist to populate the request into */
	nvl = nvlist_create(0);
	if (nvl == NULL) {
		warn("nvlist_create");
		retval = -1;
		goto done;
	}

	/* Create nvlist for a sysctl_str request */
	nvlist_add_string(nvl, "type", "sysctl_str");
	nvlist_add_string(nvl, "sysctl_str", name);

	/* XXX this sets errno as appropriate */
	retval = u_sysctl_do_sysctl(nvl, ns, oldp, oldlenp, newp, newlen);

done:
	if (nvl)
		nvlist_destroy(nvl);
	return (retval);
}

int
u_sysctl(int ns,
    int *oid,
    u_int namelen,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen)
{
	nvlist_t *nvl = NULL, *nvl_resp = NULL;
	int retval = 0;
	const char *rbuf;
	size_t r_len;
	int r_errno;

#if 0
	printf("sysctl: nl=%d, oldp=%p, oldlen=%d, newp=%p, newlen=%d\n",
	    namelen,
	    oldp,
	    (int) *oldlenp,
	    newp,
	    (int) newlen);
#endif

	/* Create nvlist to populate the request into */
	nvl = nvlist_create(0);
	if (nvl == NULL) {
		warn("nvlist_create");
		retval = -1;
		goto done;
	}

	/* Create nvlist for a sysctl_oid request */
	nvlist_add_string(nvl, "type", "sysctl_oid");
	nvlist_add_binary(nvl, "sysctl_oid", oid, namelen * sizeof(int));

	/* XXX this sets errno as appropriate */
	retval = u_sysctl_do_sysctl(nvl, ns, oldp, oldlenp, newp, newlen);

done:
	if (nvl)
		nvlist_destroy(nvl);
	return (retval);
}

int
u_sysctl_open(void)
{
	int s;
	struct sockaddr_un sun;
	int r;
	char *spath;

	spath = getenv("SYSCTL_SOCK");
	if (spath == NULL)
		spath = "/tmp/sysctl.sock";

	/* Connect to the destination socket */
	bzero(&sun, sizeof(sun));

	strcpy(sun.sun_path, spath);
	sun.sun_len = 0;
	sun.sun_family = AF_UNIX;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		err(1, "socket");
	}

	r = connect(s, (struct sockaddr *) &sun, sizeof(struct sockaddr_un));
	if (r < 0) {
		err(1, "connect");
	}

	return (s);
}
