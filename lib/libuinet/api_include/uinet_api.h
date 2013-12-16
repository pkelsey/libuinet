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


#ifndef	_UINET_API_H_
#define	_UINET_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "uinet_api_errno.h"
#include "uinet_api_types.h"
#include "uinet_config.h"

void  uinet_finalize_thread(void);
int   uinet_getl2info(struct uinet_socket *so, struct uinet_in_l2info *l2i);
char *uinet_inet_ntoa(struct uinet_in_addr in, char *buf, unsigned int size);
int   uinet_inet_pton(int af, const char *src, void *dst);
int   uinet_inet6_enabled(void);
int   uinet_init(unsigned int ncpus, unsigned int nmbclusters, unsigned int loopback);
int   uinet_initialize_thread(void);
int   uinet_interface_add_alias(const char *name, const char *addr, const char *braddr, const char *mask);
int   uinet_interface_create(const char *name);
int   uinet_interface_up(const char *name, unsigned int promisc);
int   uinet_l2tagstack_cmp(const struct uinet_in_l2tagstack *ts1, const struct uinet_in_l2tagstack *ts2);
uint32_t uinet_l2tagstack_hash(const struct uinet_in_l2tagstack *ts);
int   uinet_mac_aton(const char *macstr, uint8_t *macout);
int   uinet_make_socket_promiscuous(struct uinet_socket *so, unsigned int fib);
int   uinet_setl2info(struct uinet_socket *so, struct uinet_in_l2info *l2i);
int   uinet_setl2info2(struct uinet_socket *so, uint8_t *local_addr, uint8_t *foreign_addr,
		       uint16_t flags, struct uinet_in_l2tagstack *tagstack);
int   uinet_soaccept(struct uinet_socket *listener, struct uinet_sockaddr **nam, struct uinet_socket **aso);
int   uinet_sobind(struct uinet_socket *so, struct uinet_sockaddr *nam);
int   uinet_soclose(struct uinet_socket *so);
int   uinet_soconnect(struct uinet_socket *so, struct uinet_sockaddr *nam);
int   uinet_socreate(int dom, struct uinet_socket **aso, int type, int proto);
void  uinet_sogetconninfo(struct uinet_socket *so, struct uinet_in_conninfo *inc);
int   uinet_sogeterror(struct uinet_socket *so);
unsigned int uinet_sogetrxavail(struct uinet_socket *so);
int   uinet_sogetsockopt(struct uinet_socket *so, int level, int optname, void *optval, unsigned int *optlen);
int   uinet_sogetstate(struct uinet_socket *so);
int   uinet_solisten(struct uinet_socket *so, int backlog);
int   uinet_soreceive(struct uinet_socket *so, struct uinet_sockaddr **psa, struct uinet_uio *uio, int *flagsp);
void  uinet_sosetnonblocking(struct uinet_socket *so, unsigned int nonblocking);
int   uinet_sosetsockopt(struct uinet_socket *so, int level, int optname, void *optval, unsigned int optlen);
void  uinet_sosetupcallprep(struct uinet_socket *so,
			    void (*soup_accept)(struct uinet_socket *, void *), void *soup_accept_arg,
			    void (*soup_receive)(struct uinet_socket *, void *, int64_t, int64_t), void *soup_receive_arg,
			    void (*soup_send)(struct uinet_socket *, void *, int64_t), void *soup_send_arg);
int   uinet_sosend(struct uinet_socket *so, struct uinet_sockaddr *addr, struct uinet_uio *uio, int flags);
int   uinet_soshutdown(struct uinet_socket *so, int how);
int   uinet_sogetpeeraddr(struct uinet_socket *so, struct uinet_sockaddr **sa);
int   uinet_sogetsockaddr(struct uinet_socket *so, struct uinet_sockaddr **sa);
void  uinet_free_sockaddr(struct uinet_sockaddr *sa);
void  uinet_soupcall_lock(struct uinet_socket *so, int which);
void  uinet_soupcall_clear(struct uinet_socket *so, int which);
void  uinet_soupcall_clear_locked(struct uinet_socket *so, int which);
void  uinet_soupcall_set(struct uinet_socket *so, int which, int (*func)(struct uinet_socket *, void *, int), void *arg);
void  uinet_soupcall_set_locked(struct uinet_socket *so, int which, int (*func)(struct uinet_socket *, void *, int), void *arg);
void  uinet_soupcall_unlock(struct uinet_socket *so, int which);
void  uinet_synfilter_getconninfo(uinet_api_synfilter_cookie_t cookie, struct uinet_in_conninfo *inc);
void  uinet_synfilter_getl2info(uinet_api_synfilter_cookie_t cookie, struct uinet_in_l2info *l2i);
int   uinet_synfilter_install(struct uinet_socket *so, uinet_api_synfilter_callback_t callback, void *arg);
uinet_synf_deferral_t uinet_synfilter_deferral_alloc(struct uinet_socket *so, uinet_api_synfilter_cookie_t cookie);
int   uinet_synfilter_deferral_deliver(struct uinet_socket *so, uinet_synf_deferral_t deferral, int decision);

#ifdef __cplusplus
}
#endif

#endif /* _UINET_API_H_ */
