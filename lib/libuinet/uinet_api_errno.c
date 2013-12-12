/*
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
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


#include "uinet_api_errno.h"

#include <errno.h>


int
uinet_errno_to_os(int uinet_errno)
{
	int os_errno;

	/* XXX this will need some attention on non FreeBSD OSes */
	switch (uinet_errno) {
	case UINET_EPERM:		os_errno = EPERM; break;
	case UINET_ENOENT:		os_errno = ENOENT; break;
	case UINET_ESRCH:		os_errno = ESRCH; break;
	case UINET_EINTR:		os_errno = EINTR; break;
	case UINET_EIO:			os_errno = EIO; break;
	case UINET_ENXIO:		os_errno = ENXIO; break;
	case UINET_E2BIG:		os_errno = E2BIG; break;
	case UINET_ENOEXEC:		os_errno = ENOEXEC; break;
	case UINET_EBADF:		os_errno = EBADF; break;
	case UINET_ECHILD:		os_errno = ECHILD; break;
	case UINET_EDEADLK:		os_errno = EDEADLK; break;
	case UINET_ENOMEM:		os_errno = ENOMEM; break;
	case UINET_EACCES:		os_errno = EACCES; break;
	case UINET_EFAULT:		os_errno = EFAULT; break;
	case UINET_ENOTBLK:		os_errno = ENOTBLK; break;
	case UINET_EBUSY:		os_errno = EBUSY; break;
	case UINET_EEXIST:		os_errno = EEXIST; break;
	case UINET_EXDEV:		os_errno = EXDEV; break;
	case UINET_ENODEV:		os_errno = ENODEV; break;
	case UINET_ENOTDIR:		os_errno = ENOTDIR; break;
	case UINET_EISDIR:		os_errno = EISDIR; break;
	case UINET_EINVAL:		os_errno = EINVAL; break;
	case UINET_ENFILE:		os_errno = ENFILE; break;
	case UINET_EMFILE:		os_errno = EMFILE; break;
	case UINET_ENOTTY:		os_errno = ENOTTY; break;
	case UINET_ETXTBSY:		os_errno = ETXTBSY; break;
	case UINET_EFBIG:		os_errno = EFBIG; break;
	case UINET_ENOSPC:		os_errno = ENOSPC; break;
	case UINET_ESPIPE:		os_errno = ESPIPE; break;
	case UINET_EROFS:		os_errno = EROFS; break;
	case UINET_EMLINK:		os_errno = EMLINK; break;
	case UINET_EPIPE:		os_errno = EPIPE; break;
	case UINET_EDOM:		os_errno = EDOM; break;
	case UINET_ERANGE:		os_errno = ERANGE; break;

/*	case UINET_EAGAIN:  same as EWOULDBLOCK */
	case UINET_EWOULDBLOCK:		os_errno = EWOULDBLOCK; break;

	case UINET_EINPROGRESS:		os_errno = EINPROGRESS; break;
	case UINET_EALREADY:		os_errno = EALREADY; break;
	case UINET_ENOTSOCK:		os_errno = ENOTSOCK; break;
	case UINET_EDESTADDRREQ:	os_errno = EDESTADDRREQ; break;
	case UINET_EMSGSIZE:		os_errno = EMSGSIZE; break;
	case UINET_EPROTOTYPE:		os_errno = EPROTOTYPE; break;
	case UINET_ENOPROTOOPT:		os_errno = ENOPROTOOPT; break;
	case UINET_EPROTONOSUPPORT:	os_errno = EPROTONOSUPPORT; break;
	case UINET_ESOCKTNOSUPPORT:	os_errno = ESOCKTNOSUPPORT; break;

/*	case UINET_EOPNOTSUPP: same as ENOTSUP */
	case UINET_ENOTSUP:		os_errno = ENOTSUP; break;

	case UINET_EPFNOSUPPORT:	os_errno = EPFNOSUPPORT; break;
	case UINET_EAFNOSUPPORT:	os_errno = EAFNOSUPPORT; break;
	case UINET_EADDRINUSE:		os_errno = EADDRINUSE; break;
	case UINET_EADDRNOTAVAIL:	os_errno = EADDRNOTAVAIL; break;
	case UINET_ENETDOWN:		os_errno = ENETDOWN; break;
	case UINET_ENETUNREACH:		os_errno = ENETUNREACH; break;
	case UINET_ENETRESET:		os_errno = ENETRESET; break;
	case UINET_ECONNABORTED:	os_errno = ECONNABORTED; break;
	case UINET_ECONNRESET:		os_errno = ECONNRESET; break;
	case UINET_ENOBUFS:		os_errno = ENOBUFS; break;
	case UINET_EISCONN:		os_errno = EISCONN; break;
	case UINET_ENOTCONN:		os_errno = ENOTCONN; break;
	case UINET_ESHUTDOWN:		os_errno = ESHUTDOWN; break;
	case UINET_ETOOMANYREFS:	os_errno = ETOOMANYREFS; break;
	case UINET_ETIMEDOUT:		os_errno = ETIMEDOUT; break;
	case UINET_ECONNREFUSED:	os_errno = ECONNREFUSED; break;
	case UINET_ELOOP:		os_errno = ELOOP; break;
	case UINET_ENAMETOOLONG:	os_errno = ENAMETOOLONG; break;
	case UINET_EHOSTDOWN:		os_errno = EHOSTDOWN; break;
	case UINET_EHOSTUNREACH:	os_errno = EHOSTUNREACH; break;
	case UINET_ENOTEMPTY:		os_errno = ENOTEMPTY; break;
	case UINET_EUSERS:		os_errno = EUSERS; break;
	case UINET_EDQUOT:		os_errno = EDQUOT; break;
	case UINET_ESTALE:		os_errno = ESTALE; break;
	case UINET_EREMOTE:		os_errno = EREMOTE; break;
	case UINET_ENOLCK:		os_errno = ENOLCK; break;
	case UINET_ENOSYS:		os_errno = ENOSYS; break;
	case UINET_EIDRM:		os_errno = EIDRM; break;
	case UINET_ENOMSG:		os_errno = ENOMSG; break;
	case UINET_EOVERFLOW:		os_errno = EOVERFLOW; break;
	case UINET_ECANCELED:		os_errno = ECANCELED; break;
	case UINET_EILSEQ:		os_errno = EILSEQ; break;
	case UINET_EBADMSG:		os_errno = EBADMSG; break;
	case UINET_EMULTIHOP:		os_errno = EMULTIHOP; break;
	case UINET_ENOLINK:		os_errno = ENOLINK; break;
	case UINET_EPROTO:		os_errno = EPROTO; break;
	default:			os_errno = uinet_errno; break;
	}

	return (os_errno);
}




