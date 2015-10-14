/*
 * Copyright (c) 2014 Patrick Kelsey. All rights reserved.
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


#define UHI_CLOCK_REALTIME		0
#define UHI_CLOCK_MONOTONIC		4
#define UHI_CLOCK_MONOTONIC_FAST       12

#define UHI_NSEC_PER_SEC	(1000ULL * 1000ULL * 1000ULL)

#define UHI_TS_TO_NSEC(ts) (uint64_t)((uint64_t)((ts).tv_sec) * UHI_NSEC_PER_SEC + (ts).tv_nsec)
#define UHI_MAKE_TS(ts,sec,nsec) (ts).tv_sec = sec; (ts).tv_nsec = nsec


#define UHI_O_RDONLY	0x0000
#define UHI_O_WRONLY	0x0001
#define UHI_O_RDWR	0x0002
#define UHI_O_NONBLOCK	0x0004
#define UHI_O_APPEND	0x0008
#define UHI_O_SYNC	0x0080
#define UHI_O_CREAT	0x0200
#define UHI_O_TRUNC	0x0400
#define UHI_O_EXCL	0x0800

#define	UHI_S_IRWXU	0000700
#define	UHI_S_IRUSR	0000400
#define	UHI_S_IWUSR	0000200
#define	UHI_S_IXUSR	0000100

#define	UHI_S_IRWXG	0000070
#define	UHI_S_IRGRP	0000040
#define	UHI_S_IWGRP	0000020
#define	UHI_S_IXGRP	0000010

#define	UHI_S_IRWXO	0000007
#define	UHI_S_IROTH	0000004
#define	UHI_S_IWOTH	0000002
#define	UHI_S_IXOTH	0000001

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


typedef intptr_t uhi_thread_t;
typedef intptr_t uhi_tls_key_t;

struct uhi_thread_start_args {
#define UHI_THREAD_NAME_SIZE	32
	char name[UHI_THREAD_NAME_SIZE];
	void (*start_routine)(void *);
	void *start_routine_arg;
	void (*end_routine)(struct uhi_thread_start_args *);
	void (*start_notify_routine)(void *);
	void *start_notify_routine_arg;
	int set_tls;
	uhi_tls_key_t tls_key;
	void *tls_data;
};

typedef void (*uhi_thread_hook_t)(void *);
#define UHI_THREAD_HOOK_START		0
#define UHI_THREAD_HOOK_FINISH		1
#define UHI_THREAD_NUM_HOOK_TYPES	2

typedef void * uhi_mutex_t;

#define UHI_MTX_RECURSE	0x1


typedef void * uhi_cond_t;

typedef void * uhi_rwlock_t;

#define UHI_RW_WRECURSE 0x1


/*
 * This is opaque - don't reference the members anywhere.  The definition is
 * public to allow static allocation.
 */
struct uhi_msg {
	int fds[2];
	unsigned int size;
	unsigned int rsp_size;
};

/*
 * Enable to compile in both the lock file/line into the source tree for
 * lock debugging.
 */
#if 0
#define	UINET_LOCK_FILE		NULL
#define	UINET_LOCK_LINE		0
#else
#define	UINET_LOCK_FILE		__FILE__
#define	UINET_LOCK_LINE		__LINE__
#endif

void uhi_lock_log_init(void);
void uhi_lock_log_set_file(const char *file);
void uhi_lock_log_enable(void);
void uhi_lock_log_disable(void);

void uhi_init(void) __attribute__((constructor));
void uhi_set_num_cpus(unsigned int n);

void *uhi_malloc(uint64_t size);
void *uhi_calloc(uint64_t number, uint64_t size);
void *uhi_realloc(void *p, uint64_t size);
void  uhi_free(void *p);

void  uhi_clock_gettime(int id, int64_t *sec, long *nsec);
uint64_t  uhi_clock_gettime_ns(int id);
int   uhi_nanosleep(uint64_t nsecs);

int   uhi_open(const char *path, int flags);
int   uhi_close(int d);
int   uhi_mkdir(const char *path, unsigned int mode);
void *uhi_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset);
int   uhi_munmap(void *addr, uint64_t len);
int   uhi_poll(struct uhi_pollfd *fds, unsigned int nfds, int timeout);

void  uhi_thread_bind(unsigned int cpu);
int   uhi_thread_bound_cpu(void);
int   uhi_thread_create(uhi_thread_t *new_thread, struct uhi_thread_start_args *start_args, unsigned int stack_bytes);
void  uhi_thread_exit(void) __attribute__((__noreturn__));
int   uhi_thread_hook_add(int which, uhi_thread_hook_t hook, void *arg);
void  uhi_thread_hook_remove(int which, int id);
void  uhi_thread_run_hooks(int which);
void  uhi_thread_set_name(const char *name);
int   uhi_tls_key_create(uhi_tls_key_t *key, void (*destructor)(void *));
int   uhi_tls_key_delete(uhi_tls_key_t key);
void *uhi_tls_get(uhi_tls_key_t key);
int   uhi_tls_set(uhi_tls_key_t key, void *data);
uhi_thread_t uhi_thread_self(void);
uint64_t uhi_thread_self_id(void);
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
void  _uhi_mutex_lock(uhi_mutex_t *m, void *l, const char *file, int line);
int   _uhi_mutex_trylock(uhi_mutex_t *m, void *l, const char *file, int line);
void  _uhi_mutex_unlock(uhi_mutex_t *m, void *l, const char *file, int line);

#if 0
#define	uhi_mutex_lock(m)	_uhi_mutex_lock((m),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_mutex_trylock(m)	_uhi_mutex_trylock((m),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_mutex_unlock(m)	_uhi_mutex_unlock((m),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#endif

int   uhi_rwlock_init(uhi_rwlock_t *rw, int opts);
void  uhi_rwlock_destroy(uhi_rwlock_t *rw);
void  _uhi_rwlock_wlock(uhi_rwlock_t *rw, void *l, const char *file, int line);
int   _uhi_rwlock_trywlock(uhi_rwlock_t *rw, void *l, const char *file, int line);
void  _uhi_rwlock_wunlock(uhi_rwlock_t *rw, void *l, const char *file, int line);
void  _uhi_rwlock_rlock(uhi_rwlock_t *rw, void *l, const char *file, int line);
int   _uhi_rwlock_tryrlock(uhi_rwlock_t *rw, void *l, const char *file, int line);
void  _uhi_rwlock_runlock(uhi_rwlock_t *rw, void *l, const char *file, int line);
int   _uhi_rwlock_tryupgrade(uhi_rwlock_t *rw, void *l, const char *file, int line);
void  _uhi_rwlock_downgrade(uhi_rwlock_t *rw, void *l, const char *file, int line);

#if 0
#define	uhi_rwlock_wlock(rw)	_uhi_rwlock_wlock((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_trywlock(rw)	_uhi_rwlock_trywlock((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_wunlock(rw)	_uhi_rwlock_wunlock((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_rlock(rw)	_uhi_rwlock_rlock((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_tryrlock(rw)	_uhi_rwlock_tryrlock((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_runlock(rw)	_uhi_rwlock_runlock((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_tryupgrade(rw)	_uhi_rwlock_tryupgrade((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#define	uhi_rwlock_downgrade(rw)	_uhi_rwlock_downgrade((rw),	\
				    UINET_LOCK_FILE, UINET_LOCK_LINE)
#endif

int   uhi_get_ifaddr(const char *ifname, uint8_t *ethaddr);

void  uhi_arc4rand(void *ptr, unsigned int len, int reseed);
uint32_t uhi_arc4random(void);

void  uhi_install_sighandlers(void);
void  uhi_mask_all_signals(void);
void  uhi_unmask_all_signals(void);

int uhi_msg_init(struct uhi_msg *msg, unsigned int size, unsigned int rsp_size);
void uhi_msg_destroy(struct uhi_msg *msg);
int uhi_msg_send(struct uhi_msg *msg, void *payload);
int uhi_msg_wait(struct uhi_msg *msg, void *payload);
int uhi_msg_rsp_send(struct uhi_msg *msg, void *payload);
int uhi_msg_rsp_wait(struct uhi_msg *msg, void *payload);

int uhi_get_stacktrace(uintptr_t *pcs, int npcs);

#endif /* _UINET_HOST_INTERFACE_H_ */
