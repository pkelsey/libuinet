#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/endian.h>

#include "u_sysctl.h"
#include "nv.h"

int
main(int argc, char *argv[])
{

	int s;
	int r;
	size_t reqbuf_len = 0, respbuf_len = 0;
	char *req_str;
	char *req_buf = NULL;
	char *resp_buf;
	size_t r_len;

	if (argc < 2) {
		printf("Usage: sysctl <sysctl string>\n");
		exit(127);
	}

	/* Fake up a request structure for now */
	req_str = strdup(argv[1]);
	reqbuf_len = 0;
	respbuf_len = 1048576;

	/* XXX Reqbuf when required */

	s = u_sysctl_open();
	if (s < 0) {
		err(1, "socket");
	}

	resp_buf = calloc(1, respbuf_len);
	if (resp_buf == NULL)
		err(1, "calloc");

#if 1
	/* Do a sysctl */
	r = u_sysctlbyname(s, req_str, resp_buf, &respbuf_len,
	    NULL, 0);
	printf("%s: str=%s, r=%d, errno=%d, len=%d\n",
	    __func__,
	    req_str,
	    r,
	    errno,
	    (int) respbuf_len);
#else
	/* Do a sysctl */
	int oida[2];
	oida[0] = 1;
	oida[1] = 6;
	r = u_sysctl(s, oida, 2, resp_buf, &respbuf_len,
	    NULL, 0);
	printf("%s: str=%s, r=%d, errno=%d, len=%d\n",
	    __func__,
	    req_str,
	    r,
	    errno,
	    (int) respbuf_len);
#endif

	/* Done */
	if (req_str)
		free(req_str);

done:

	/* Done with socket */
	close(s);

	exit(0);
}
