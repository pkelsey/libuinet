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


#ifndef	_UINET_API_ERRNO_H_
#define	_UINET_API_ERRNO_H_

#define	UINET_EPERM		1		/* Operation not permitted */
#define	UINET_ENOENT		2		/* No such file or directory */
#define	UINET_ESRCH		3		/* No such process */
#define	UINET_EINTR		4		/* Interrupted system call */
#define	UINET_EIO		5		/* Input/output error */
#define	UINET_ENXIO		6		/* Device not configured */
#define	UINET_E2BIG		7		/* Argument list too long */
#define	UINET_ENOEXEC		8		/* Exec format error */
#define	UINET_EBADF		9		/* Bad file descriptor */
#define	UINET_ECHILD		10		/* No child processes */
#define	UINET_EDEADLK		11		/* Resource deadlock avoided */
						/* 11 was EAGAIN */
#define	UINET_ENOMEM		12		/* Cannot allocate memory */
#define	UINET_EACCES		13		/* Permission denied */
#define	UINET_EFAULT		14		/* Bad address */
#define	UINET_ENOTBLK		15		/* Block device required */
#define	UINET_EBUSY		16		/* Device busy */
#define	UINET_EEXIST		17		/* File exists */
#define	UINET_EXDEV		18		/* Cross-device link */
#define	UINET_ENODEV		19		/* Operation not supported by device */
#define	UINET_ENOTDIR		20		/* Not a directory */
#define	UINET_EISDIR		21		/* Is a directory */
#define	UINET_EINVAL		22		/* Invalid argument */
#define	UINET_ENFILE		23		/* Too many open files in system */
#define	UINET_EMFILE		24		/* Too many open files */
#define	UINET_ENOTTY		25		/* Inappropriate ioctl for device */
#define	UINET_ETXTBSY		26		/* Text file busy */
#define	UINET_EFBIG		27		/* File too large */
#define	UINET_ENOSPC		28		/* No space left on device */
#define	UINET_ESPIPE		29		/* Illegal seek */
#define	UINET_EROFS		30		/* Read-only filesystem */
#define	UINET_EMLINK		31		/* Too many links */
#define	UINET_EPIPE		32		/* Broken pipe */

/* math software */
#define	UINET_EDOM		33		/* Numerical argument out of domain */
#define	UINET_ERANGE		34		/* Result too large */

/* non-blocking and interrupt i/o */
#define	UINET_EAGAIN		35		/* Resource temporarily unavailable */
#define	UINET_EWOULDBLOCK	UINET_EAGAIN		/* Operation would block */
#define	UINET_EINPROGRESS	36		/* Operation now in progress */
#define	UINET_EALREADY		37		/* Operation already in progress */

/* ipc/network software -- argument errors */
#define	UINET_ENOTSOCK		38		/* Socket operation on non-socket */
#define	UINET_EDESTADDRREQ	39		/* Destination address required */
#define	UINET_EMSGSIZE		40		/* Message too long */
#define	UINET_EPROTOTYPE	41		/* Protocol wrong type for socket */
#define	UINET_ENOPROTOOPT	42		/* Protocol not available */
#define	UINET_EPROTONOSUPPORT	43		/* Protocol not supported */
#define	UINET_ESOCKTNOSUPPORT	44		/* Socket type not supported */
#define	UINET_EOPNOTSUPP	45		/* Operation not supported */
#define	UINET_ENOTSUP		UINET_EOPNOTSUPP	/* Operation not supported */
#define	UINET_EPFNOSUPPORT	46		/* Protocol family not supported */
#define	UINET_EAFNOSUPPORT	47		/* Address family not supported by protocol family */
#define	UINET_EADDRINUSE	48		/* Address already in use */
#define	UINET_EADDRNOTAVAIL	49		/* Can't assign requested address */

/* ipc/network software -- operational errors */
#define	UINET_ENETDOWN		50		/* Network is down */
#define	UINET_ENETUNREACH	51		/* Network is unreachable */
#define	UINET_ENETRESET		52		/* Network dropped connection on reset */
#define	UINET_ECONNABORTED	53		/* Software caused connection abort */
#define	UINET_ECONNRESET	54		/* Connection reset by peer */
#define	UINET_ENOBUFS		55		/* No buffer space available */
#define	UINET_EISCONN		56		/* Socket is already connected */
#define	UINET_ENOTCONN		57		/* Socket is not connected */
#define	UINET_ESHUTDOWN		58		/* Can't send after socket shutdown */
#define	UINET_ETOOMANYREFS	59		/* Too many references: can't splice */
#define	UINET_ETIMEDOUT		60		/* Operation timed out */
#define	UINET_ECONNREFUSED	61		/* Connection refused */

#define	UINET_ELOOP		62		/* Too many levels of symbolic links */
#define	UINET_ENAMETOOLONG	63		/* File name too long */

/* should be rearranged */
#define	UINET_EHOSTDOWN		64		/* Host is down */
#define	UINET_EHOSTUNREACH	65		/* No route to host */
#define	UINET_ENOTEMPTY		66		/* Directory not empty */

/* quotas & mush */
#define	UINET_EPROCLIM		67		/* Too many processes */
#define	UINET_EUSERS		68		/* Too many users */
#define	UINET_EDQUOT		69		/* Disc quota exceeded */

/* Network File System */
#define	UINET_ESTALE		70		/* Stale NFS file handle */
#define	UINET_EREMOTE		71		/* Too many levels of remote in path */
#define	UINET_EBADRPC		72		/* RPC struct is bad */
#define	UINET_ERPCMISMATCH	73		/* RPC version wrong */
#define	UINET_EPROGUNAVAIL	74		/* RPC prog. not avail */
#define	UINET_EPROGMISMATCH	75		/* Program version wrong */
#define	UINET_EPROCUNAVAIL	76		/* Bad procedure for program */

#define	UINET_ENOLCK		77		/* No locks available */
#define	UINET_ENOSYS		78		/* Function not implemented */

#define	UINET_EFTYPE		79		/* Inappropriate file type or format */
#define	UINET_EAUTH		80		/* Authentication error */
#define	UINET_ENEEDAUTH		81		/* Need authenticator */
#define	UINET_EIDRM		82		/* Identifier removed */
#define	UINET_ENOMSG		83		/* No message of desired type */
#define	UINET_EOVERFLOW		84		/* Value too large to be stored in data type */
#define	UINET_ECANCELED		85		/* Operation canceled */
#define	UINET_EILSEQ		86		/* Illegal byte sequence */
#define	UINET_ENOATTR		87		/* Attribute not found */

#define	UINET_EDOOFUS		88		/* Programming error */

#define	UINET_EBADMSG		89		/* Bad message */
#define	UINET_EMULTIHOP		90		/* Multihop attempted */
#define	UINET_ENOLINK		91		/* Link has been severed */
#define	UINET_EPROTO		92		/* Protocol error */

#define	UINET_ENOTCAPABLE	93		/* Capabilities insufficient */
#define	UINET_ECAPMODE		94		/* Not permitted in capability mode */

#define	UINET_ELAST		94		/* Must be equal largest errno */

#ifdef __cplusplus
extern "C" {
#endif

int uinet_errno_to_os(int uinet_errno);

#ifdef __cplusplus
}
#endif

#endif /* _UINET_API_ERRNO_H_ */
