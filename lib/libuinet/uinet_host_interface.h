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


#ifndef	_UINET_HOST_INTERFACE_H_
#define	_UINET_HOST_INTERFACE_H_


#define UHI_CLOCK_REALTIME	0
#define UHI_CLOCK_MONOTONIC	4

#define UHI_TS_TO_NSEC(ts) (uint64_t)((uint64_t)((ts).tv_sec) * 1000UL * 1000UL * 1000UL + (ts).tv_nsec)


#define UHI_O_RDONLY	0x0000
#define UHI_O_WRONLY	0x0001
#define UHI_O_RDWR	0x0002
#define UHI_O_NONBLOCK	0x0004
#define UHI_O_APPEND	0x0008
#define UHI_O_SYNC	0x0080
#define UHI_O_CREAT	0x0200
#define UHI_O_TRUNC	0x0400
#define UHI_O_EXCL	0x0800


struct uhi_pollfd {
	int	fd;
	short	events;
	short	revents;
};

#define	UHI_POLLIN	0x0001
#define	UHI_POLLPRI	0x0002
#define	UHI_POLLOUT	0x0004
#define	UHI_POLLERR	0x0008
#define	UHI_POLLHUP	0x0010
#define	UHI_POLLNVAL	0x0020


#define	UHI_PROT_NONE	0x00
#define	UHI_PROT_READ	0x01
#define	UHI_PROT_WRITE	0x02

#define	UHI_MAP_SHARED	0x0001
#define	UHI_MAP_PRIVATE	0x0002
#define UHI_MAP_ANON	0x1000
#define	UHI_MAP_NOCORE	0x00020000

#define UHI_MAP_FAILED	((void *)-1)


typedef void * uhi_thread_t;

struct uhi_thread_start_args {
#define UHI_THREAD_NAME_SIZE	32
	char name[UHI_THREAD_NAME_SIZE];
	void (*start_routine)(void *);
	void *start_routine_arg;
	void (*end_routine)(struct uhi_thread_start_args *);
	void *thread_specific_data;  /* will be freed when thread exits */
	uhi_thread_t *host_thread_id;
};


typedef void * uhi_mutex_t;

#define UHI_MTX_RECURSE	0x1


typedef void * uhi_cond_t;

typedef void * uhi_rwlock_t;

#define UHI_RW_WRECURSE 0x1


void uhi_init(void) __attribute__((constructor));

void *uhi_malloc(uint64_t size);
void *uhi_calloc(uint64_t number, uint64_t size);
void *uhi_realloc(void *p, uint64_t size);
void  uhi_free(void *p);

void  uhi_clock_gettime(int id, int64_t *sec, long *nsec);
int   uhi_nanosleep(uint64_t nsecs);

int   uhi_open(const char *path, int flags);
int   uhi_close(int d);
void *uhi_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset);
int   uhi_munmap(void *addr, uint64_t len);
int   uhi_poll(struct uhi_pollfd *fds, unsigned int nfds, int timeout);

void  uhi_thread_bind(unsigned int cpu);
int   uhi_thread_create(uhi_thread_t *new_thread, struct uhi_thread_start_args *start_args, unsigned int stack_bytes);
void  uhi_thread_exit(void) __attribute__((__noreturn__));
void *uhi_thread_get_thread_specific_data(void);
int   uhi_thread_set_thread_specific_data(void *data);
uhi_thread_t uhi_thread_self(void);
void  uhi_thread_yield(void);
int   uhi_thread_setprio(unsigned int prio);
int   uhi_thread_setprio_rt(unsigned int prio);

int  uhi_cond_init(uhi_cond_t *c);
void uhi_cond_destroy(uhi_cond_t *c);
void uhi_cond_wait(uhi_cond_t *c, uhi_mutex_t *m);
int  uhi_cond_timedwait(uhi_cond_t *c, uhi_mutex_t *m, uint64_t nsecs);
void uhi_cond_signal(uhi_cond_t *c);
void uhi_cond_broadcast(uhi_cond_t *c);

int   uhi_mutex_init(uhi_mutex_t *m, int opts);
void  uhi_mutex_destroy(uhi_mutex_t *m);
void  uhi_mutex_lock(uhi_mutex_t *m);
int   uhi_mutex_trylock(uhi_mutex_t *m);
void  uhi_mutex_unlock(uhi_mutex_t *m);

int   uhi_rwlock_init(uhi_rwlock_t *rw, int opts);
void  uhi_rwlock_destroy(uhi_rwlock_t *rw);
void  uhi_rwlock_wlock(uhi_rwlock_t *rw);
int   uhi_rwlock_trywlock(uhi_rwlock_t *rw);
void  uhi_rwlock_wunlock(uhi_rwlock_t *rw);
void  uhi_rwlock_rlock(uhi_rwlock_t *rw);
int   uhi_rwlock_tryrlock(uhi_rwlock_t *rw);
void  uhi_rwlock_runlock(uhi_rwlock_t *rw);
int   uhi_rwlock_tryupgrade(uhi_rwlock_t *rw);
void  uhi_rwlock_downgrade(uhi_rwlock_t *rw);

#endif /* _UINET_HOST_INTERFACE_H_ */
