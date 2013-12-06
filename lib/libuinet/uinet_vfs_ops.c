/*-
 * Copyright (c) 2011 Kip Macy
 * All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Derived in part from libplebnet's pn_vfs_ops.c.
 *
 */

#include <uinet_sys/cdefs.h>
#undef _KERNEL
#include <errno.h>
#define _KERNEL
#include <uinet_sys/param.h>
#include <uinet_sys/types.h>
#include <uinet_sys/limits.h>
#include <uinet_sys/malloc.h>
#include <uinet_sys/namei.h>
#include <uinet_sys/refcount.h>
#include <uinet_sys/resourcevar.h>
#include <uinet_sys/systm.h>
#include <uinet_sys/proc.h>
#include <uinet_sys/priv.h>
#include <uinet_sys/time.h>
#include <uinet_sys/ucred.h>
#include <uinet_sys/vnode.h>
#include <uinet_sys/uio.h>
#undef _KERNEL
#include <fcntl.h>
#include <sys/mman.h>
#include <link.h>
#include <dlfcn.h>


int	close(int d);
int	pread(int d, const char *buf, int bytes, off_t offset);

void
NDFREE(struct nameidata *ndp, const u_int flags)
{

}

int	
vn_open(struct nameidata *ndp, int *flagp, int cmode, struct file *fp)
{
	struct vnode *vp;
	int fd;

	if ((fd = open(ndp->ni_dirp, O_RDONLY)) < 0) 
		return (errno);

	if ((vp = malloc(sizeof(struct vnode), M_DEVBUF, M_WAITOK)) == NULL) {
		close(fd);
		return (ENOMEM);
	}

	vp->v_fd = fd;
	vp->v_type = VREG;
	ndp->ni_vp = vp;
	return (0);
}


int	
vn_close(struct vnode *vp,
	    int flags, struct ucred *file_cred, struct thread *td)
{
	int err;

	err = close(vp->v_fd);
	free(vp, M_DEVBUF);
	return (err);
}

int	
vn_rdwr(enum uio_rw rw, struct vnode *vp, void *base,
	    int len, off_t offset, enum uio_seg segflg, int ioflg,
	    struct ucred *active_cred, struct ucred *file_cred, ssize_t *aresid,
	    struct thread *td)
{
	int bytesread;

	bytesread = pread(vp->v_fd, base, len, offset);
	if (bytesread < 0)
		return (errno);

	*aresid = len - bytesread;
	return (0);
}

#ifdef notneeded
int
uinet_map_object(size_t mapsize, vm_offset_t *mapbase)
{
	void *addr;

	addr = mmap(NULL, mapsize, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0);

	if (addr == NULL)
		return (ENOMEM);

	*mapbase = (vm_offset_t)addr;
	return (0);
}

const void *
uinet_get_dynamic(void)
{
	struct link_map *map;
	int err;


	if ((err = dlinfo(RTLD_SELF, RTLD_DI_LINKMAP, (void *)&map)))
		return (NULL);

	return (map->l_ld);
}

const void *
uinet_get_address(void)
{
	struct link_map *map;
	int err;


	if ((err = dlinfo(RTLD_SELF, RTLD_DI_LINKMAP, (void *)&map)))
		return (NULL);

	return (map->l_addr);
}
#endif
