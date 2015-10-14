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

#if defined(__linux__)
/*
 * To expose:
 *     CPU_SET()
 *     CPU_ZERO()
 *
 *     pthread_setaffinity_np()
 *     pthread_setname_np()
 *
 */
#define _GNU_SOURCE
#endif /* __linux__ */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif /* __FreeBSD__ */
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#else
#include <openssl/rand.h>
#endif

#include <net/ethernet.h>
#if defined(__FreeBSD__)
#include <net/if.h>
#include <net/if_dl.h>
#endif /*  __FreeBSD__ */

#if defined(__linux__)
#include <netpacket/packet.h>
#endif /* __linux__ */

#include <ifaddrs.h>

#if defined(__FreeBSD__)
#include <sys/cpuset.h>
#endif /* __FreeBSD__ */

#include <sys/mman.h>
#include <sys/stat.h>

#include "uinet_api.h"
#include "uinet_host_interface.h"


#if defined(__linux__)
typedef cpu_set_t cpuset_t;
#endif /* __linux__ */


#if defined(UINET_PROFILE)
#include <sys/time.h>

static struct itimerval prof_itimer;
#endif /* UINET_PROFILE */

#if defined(UINET_STACK_UNWIND)
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif /* UINET_STACK_UNWIND */

static unsigned int uhi_num_cpus;

static uhi_mutex_t uhi_thread_hook_lock;
static uhi_tls_key_t uhi_thread_tls_key;

#define UHI_MAX_THREAD_HOOKS 16
static struct {
	uhi_thread_hook_t hook;
	void *arg;
} uhi_thread_hook_table[UHI_THREAD_NUM_HOOK_TYPES][UHI_MAX_THREAD_HOOKS];

static FILE *lock_log_fp = NULL;
static pthread_mutex_t lock_log_mtx;
static int lock_log_enabled = 0;
static char *lock_log_filename = NULL;

static void uhi_thread_tls_destructor(void *arg);

void
uhi_lock_log_init(void)
{

	pthread_mutex_init(&lock_log_mtx, NULL);
}

void
uhi_lock_log_set_file(const char *file)
{

	pthread_mutex_lock(&lock_log_mtx);
	if (lock_log_filename)
		free(lock_log_filename);
	lock_log_filename = strdup(file);
	pthread_mutex_unlock(&lock_log_mtx);
}

void
uhi_lock_log_enable(void)
{

	pthread_mutex_lock(&lock_log_mtx);
	if (lock_log_enabled == 1) {
		pthread_mutex_unlock(&lock_log_mtx);
		return;
	}

	lock_log_fp = fopen(lock_log_filename, "w+");
	lock_log_enabled = 1;
	pthread_mutex_unlock(&lock_log_mtx);
}

void
uhi_lock_log_disable(void)
{
	FILE *fp = NULL;

	pthread_mutex_lock(&lock_log_mtx);
	if (lock_log_enabled == 0) {
		pthread_mutex_unlock(&lock_log_mtx);
		return;
	}
	fp = lock_log_fp;
	lock_log_fp = NULL;
	lock_log_enabled = 0;
	pthread_mutex_unlock(&lock_log_mtx);

	/* This may take some time, so do it out of the lock */
	fclose(fp);
}

static void
uhi_lock_log(const char *type, const char *what, void *lp, void *ptr, const char *file, int line)
{
	uhi_thread_t curthr;
	int64_t sec;
	long nsec;

	if (lock_log_enabled == 0)
		return;

	uhi_clock_gettime(UHI_CLOCK_MONOTONIC_FAST, &sec, &nsec);

	curthr = uhi_thread_self();

	/*
	 * Use pthread_mutex_* calls instead of uhi_mutex_* calls here to
	 * avoid recursive lock logging.
	 */
	pthread_mutex_lock(&lock_log_mtx);
	if (lock_log_fp != NULL) {
		fprintf(lock_log_fp,
		    "%llu.%06llu: lp %p tid %x type %s what %s where %s:%d ptr %p\n",
		    (unsigned long long) (sec),
		    (unsigned long long) (nsec / 1000),
		    lp,
		    (int) curthr,
		    type,
		    what,
		    file,
		    line,
		    ptr);
	}
	pthread_mutex_unlock(&lock_log_mtx);
}


void
uhi_init(void)
{
	/*
	 * We don't translate these in our poll wrapper.
	 */
	assert(UHI_POLLIN == POLLIN);
	assert(UHI_POLLPRI == POLLPRI);
	assert(UHI_POLLOUT == POLLOUT);
	assert(UHI_POLLERR == POLLERR);
	assert(UHI_POLLHUP == POLLHUP);
	assert(UHI_POLLNVAL == POLLNVAL);
	
	/* Ensure that a pthread_t can be stored in a uhi_thread_t. */
	assert(sizeof(uhi_thread_t) >= sizeof(pthread_t));

	/* Ensure that a pthread_key_t can be stored in a uhi_tls_key_t. */
	assert(sizeof(uhi_tls_key_t) >= sizeof(pthread_key_t));

	/* Ensure that a pthread_t can be stored in a uint64_t */
	assert(sizeof(uint64_t) >= sizeof(pthread_t));

	if (uhi_tls_key_create(&uhi_thread_tls_key, uhi_thread_tls_destructor))
		printf("Could not create uhi thread subsystem tls key");

	if (uhi_mutex_init(&uhi_thread_hook_lock, 0))
		printf("Could not init uhi thread hook table lock");

	uhi_lock_log_init();

#if defined(UINET_PROFILE)
	printf("getting prof timer\n");
	getitimer(ITIMER_PROF, &prof_itimer);
#endif /* UINET_PROFILE */

}


void
uhi_set_num_cpus(unsigned int n)
{
	uhi_num_cpus = n;
}


void *
uhi_malloc(uint64_t size)
{
	return (malloc(size));
}


void *
uhi_calloc(uint64_t number, uint64_t size)
{
	return (calloc(number, size));
}


void *
uhi_realloc(void *p, uint64_t size)
{
	if (size)
		return (realloc(p, size));

	return (p);
}


void
uhi_free(void *p)
{
	free(p);
}


void
uhi_clock_gettime(int id, int64_t *sec, long *nsec)
{
#if defined(__APPLE__)
	clock_serv_t clock;
	mach_timespec_t ts;

	switch (id) {
	case UHI_CLOCK_REALTIME:
		host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &clock);
		break;
	case UHI_CLOCK_MONOTONIC:
	case UHI_CLOCK_MONOTONIC_FAST:
	default:
		host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &clock);
		break;
	}
	clock_get_time(clock, &ts);
	mach_port_deallocate(mach_task_self(), clock);
	*sec = ts.tv_sec;
	*nsec = ts.tv_nsec;
#else
	struct timespec ts;
	int host_id;
	int rv;

	switch (id) {
	case UHI_CLOCK_REALTIME:
		host_id = CLOCK_REALTIME;
		break;
#ifdef CLOCK_MONOTONIC_FAST
	case UHI_CLOCK_MONOTONIC_FAST:
		host_id = CLOCK_MONOTONIC_FAST;
		break;
#endif
	case UHI_CLOCK_MONOTONIC:
	default:
		host_id = CLOCK_MONOTONIC;
		break;
	}

	rv = clock_gettime(host_id, &ts);
	assert(0 == rv);

	*sec = (int64_t)ts.tv_sec;
	*nsec = (long)ts.tv_nsec;
#endif /* __APPLE__ */
}


uint64_t
uhi_clock_gettime_ns(int id)
{
	int64_t sec;
	long nsec;
	 
	uhi_clock_gettime(id, &sec, &nsec);

	return ((uint64_t)sec * UHI_NSEC_PER_SEC + nsec);
}


/*
 *  Sleeps for at least the given number of nanoseconds and returns 0,
 *  unless there is a non-EINTR failure, in which case a non-zero value is
 *  returned.
 */
int
uhi_nanosleep(uint64_t nsecs)
{
	struct timespec ts;
	struct timespec rts;
	int rv;

	ts.tv_sec = nsecs / UHI_NSEC_PER_SEC;
	ts.tv_nsec = nsecs % UHI_NSEC_PER_SEC;
	while ((-1 == (rv = nanosleep(&ts, &rts))) && (EINTR == errno)) {
		ts = rts;
	}
	if (-1 == rv) {
		rv = errno;
	}

	return (rv);
}

int
uhi_open(const char *path, int flags)
{
	int host_flags;

	/* Ensure 0 means read-only on both sides */
	assert(UHI_O_RDONLY == O_RDONLY);

	host_flags = 0;
	if ((flags & UHI_O_WRONLY) == UHI_O_WRONLY)     host_flags |= O_WRONLY;
	if ((flags & UHI_O_RDWR) == UHI_O_RDWR)         host_flags |= O_RDWR;
	if ((flags & UHI_O_NONBLOCK) == UHI_O_NONBLOCK) host_flags |= O_NONBLOCK;
	if ((flags & UHI_O_APPEND) == UHI_O_APPEND)     host_flags |= O_APPEND;
	if ((flags & UHI_O_SYNC) == UHI_O_SYNC)         host_flags |= O_SYNC;
	if ((flags & UHI_O_CREAT) == UHI_O_CREAT)       host_flags |= O_CREAT;
	if ((flags & UHI_O_TRUNC) == UHI_O_TRUNC)       host_flags |= O_TRUNC;
	if ((flags & UHI_O_EXCL) == UHI_O_EXCL)         host_flags |= O_EXCL;

	return (open(path, host_flags));
}


int
uhi_close(int d)
{
	return (close(d));
}


int
uhi_mkdir(const char *path, unsigned int mode)
{
	unsigned int host_mode;

	host_mode = 0;
	if ((mode & UHI_S_IRWXU) == UHI_S_IRWXU)
		host_mode |= S_IRWXU;
	else {
		if ((mode & UHI_S_IRUSR) == UHI_S_IRUSR) host_mode |= S_IRUSR;
		if ((mode & UHI_S_IWUSR) == UHI_S_IWUSR) host_mode |= S_IWUSR;
		if ((mode & UHI_S_IXUSR) == UHI_S_IXUSR) host_mode |= S_IXUSR;
	}
	if ((mode & UHI_S_IRWXG) == UHI_S_IRWXG)
		host_mode |= S_IRWXG;
	else {
		if ((mode & UHI_S_IRGRP) == UHI_S_IRGRP) host_mode |= S_IRGRP;
		if ((mode & UHI_S_IWGRP) == UHI_S_IWGRP) host_mode |= S_IWGRP;
		if ((mode & UHI_S_IXGRP) == UHI_S_IXGRP) host_mode |= S_IXGRP;
	}
	if ((mode & UHI_S_IRWXO) == UHI_S_IRWXO)
		host_mode |= S_IRWXO;
	else {
		if ((mode & UHI_S_IROTH) == UHI_S_IROTH) host_mode |= S_IROTH;
		if ((mode & UHI_S_IWOTH) == UHI_S_IWOTH) host_mode |= S_IWOTH;
		if ((mode & UHI_S_IXOTH) == UHI_S_IXOTH) host_mode |= S_IXOTH;
	}

	if (mkdir(path, host_mode))
		return (errno);
	else
		return (0);
}

void *
uhi_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset)
{
	int host_prot;
	int host_flags;

	assert(UHI_PROT_NONE == PROT_NONE);
	host_prot = 0;
	if ((prot & UHI_PROT_READ) == UHI_PROT_READ)   host_prot |= PROT_READ;
	if ((prot & UHI_PROT_WRITE) == UHI_PROT_WRITE) host_prot |= PROT_WRITE;

	host_flags = 0;
	if ((flags & UHI_MAP_SHARED) == UHI_MAP_SHARED)   host_flags |= MAP_SHARED;
	if ((flags & UHI_MAP_PRIVATE) == UHI_MAP_PRIVATE) host_flags |= MAP_PRIVATE;
	if ((flags & UHI_MAP_ANON) == UHI_MAP_ANON)       host_flags |= MAP_ANON;
#if defined(__FreeBSD__)
	if ((flags & UHI_MAP_NOCORE) == UHI_MAP_NOCORE)   host_flags |= MAP_NOCORE;
#endif

	return (mmap(addr, len, host_prot, host_flags, fd, offset));
}


int
uhi_munmap(void *addr, uint64_t len)
{
	return (munmap(addr, len));
}


/*
 *  In addition to normal poll() return values, this returns -2 to indicate
 *  poll() returned -1 and errno was EINTR.  This avoids having to do
 *  host-to-UINET errno translation here or at the call site.
 */
int
uhi_poll(struct uhi_pollfd *fds, unsigned int nfds, int timeout)
{
	int rv;

	rv = poll((struct pollfd *)fds, nfds, timeout);
	if (-1 == rv && EINTR == errno)
		rv = -2;

	return (rv);
}



void uhi_thread_bind(unsigned int cpu)
{
#if defined(__APPLE__)
	mach_port_t mach_thread = pthread_mach_thread_np(pthread_self());
	thread_affinity_policy_data_t policy_data = { cpu + 1 };   /* cpu + 1 to avoid using THREAD_AFFINITY_TAG_NULL */
	thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy_data, THREAD_AFFINITY_POLICY_COUNT);
#else
	cpuset_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu % CPU_SETSIZE, &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpuset);
#endif /* __APPLE__ */
}


int uhi_thread_bound_cpu()
{
#if defined(__APPLE__)
	mach_port_t mach_thread = pthread_mach_thread_np(pthread_self());
	thread_affinity_policy_data_t policy_data;
	mach_msg_type_number_t count = THREAD_AFFINITY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	int bound_cpu;
	thread_policy_get(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy_data, &count, &get_default);

	bound_cpu = (int)policy_data.affinity_tag - 1;
	
	/* 
	 * Thread affinity tags are arbitrary values.  We guard against this
	 * routine being invoked in a thread whose tag has been adjusted by
	 * the application as best we can.  We can't detect this happening
	 * if the application is using a tag that is also a valid CPU number
	 * of course, but we can detect if it's out of bounds and at least
	 * treat that case as an unknown binding.
	 */
	if (bound_cpu >= uhi_num_cpus)
		bound_cpu = -1;

	return (bound_cpu);
#else
	cpuset_t cpuset;
	int bound_cpu;
	int i;

	pthread_getaffinity_np(pthread_self(), sizeof(cpuset_t), &cpuset);

	/*
	 * If the cpuset contains only one CPU, then that's the answer.  For
	 * all other cpuset contents, we treat the binding as unknown.
	 */
	bound_cpu = -1;
	for (i = 0; i < uhi_num_cpus; i++) {
		if (CPU_ISSET(i, &cpuset)) {
			if (-1 == bound_cpu) {
				bound_cpu = i;
			} else {
				bound_cpu = -1;
				break;
			}
				
		}
	}

	return (bound_cpu);
#endif /* __APPLE__ */
}


static void
uhi_thread_tls_destructor(void *arg)
{
	struct uhi_thread_start_args *tsa = arg;

	if (tsa->end_routine != NULL)
		tsa->end_routine(tsa);

	uhi_thread_run_hooks(UHI_THREAD_HOOK_FINISH);
	free(tsa);
}


static void *
pthread_start_routine(void *arg)
{
	struct uhi_thread_start_args *tsa = arg;
	int error;

	/*
	 * uinet_shutdown() waits for a message from the shutdown thread
	 * indicating shutdown is complete.  If uinet_shutdown() is called
	 * from a signal handler running in a thread context that is holding
	 * a lock that the shutdown activity needs to acquire in order to
	 * complete, deadlock will occur.  Masking all signals in all
	 * internal uinet threads prevents such a deadlock by preventing all
	 * signal handlers (and thus any that might call uinet_shutdown())
	 * from running in the context of any thread that might be holding a
	 * lock required by the shutdown thread.
	 */
	uhi_mask_all_signals();

#if defined(UINET_PROFILE)
	setitimer(ITIMER_PROF, &prof_itimer, NULL);
#endif /* UINET_PROFILE */

	if (tsa->set_tls) {
		error = uhi_tls_set(tsa->tls_key, tsa->tls_data);
		if (error != 0)
			printf("Warning: unable to set user-supplied thread-specific data (%d)\n", error);
	}

	error = uhi_tls_set(uhi_thread_tls_key, tsa);
	if (error != 0)
		printf("Warning: unable to set uhi thread-specific data (%d)\n", error);

	uhi_thread_set_name(tsa->name);

	uhi_thread_run_hooks(UHI_THREAD_HOOK_START);

	if (tsa->start_notify_routine)
		tsa->start_notify_routine(tsa->start_notify_routine_arg);

	tsa->start_routine(tsa->start_routine_arg);

	return (NULL);
}


int
uhi_thread_create(uhi_thread_t *new_thread, struct uhi_thread_start_args *start_args, unsigned int stack_bytes)
{
	int error;
	pthread_t thread;
	pthread_attr_t attr;

	
	pthread_attr_init(&attr); 
	if (stack_bytes) {
		pthread_attr_setstacksize(&attr, stack_bytes);
	}

	error = pthread_create(&thread, &attr, pthread_start_routine, start_args);
	pthread_attr_destroy(&attr);

	if (new_thread)
		*new_thread = (uhi_thread_t)thread;

	return (error);
	
}


void
uhi_thread_exit(void)
{
	pthread_exit(NULL);
}


int
uhi_thread_hook_add(int which, uhi_thread_hook_t hook, void *arg)
{
	int i;

	assert(which < UHI_THREAD_NUM_HOOK_TYPES);

	_uhi_mutex_lock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
	for (i = 0; i < UHI_MAX_THREAD_HOOKS; i++)
		if (uhi_thread_hook_table[which][i].hook == NULL) {
			uhi_thread_hook_table[which][i].hook = hook;
			uhi_thread_hook_table[which][i].arg = arg;
			_uhi_mutex_unlock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
			return (i + 1);
		}

	_uhi_mutex_unlock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
	return (0);
}


void
uhi_thread_hook_remove(int which, int id)
{
	assert(which < UHI_THREAD_NUM_HOOK_TYPES);
	assert(id < UHI_MAX_THREAD_HOOKS);

	_uhi_mutex_lock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
	uhi_thread_hook_table[which][id].hook = NULL;
	_uhi_mutex_unlock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
}


void
uhi_thread_run_hooks(int which)
{
	int i;

	assert(which < UHI_THREAD_NUM_HOOK_TYPES);

	_uhi_mutex_lock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
	for (i = 0; i < UHI_MAX_THREAD_HOOKS; i++)
		if (uhi_thread_hook_table[which][i].hook)
			uhi_thread_hook_table[which][i].hook(uhi_thread_hook_table[which][i].arg);
	_uhi_mutex_unlock(&uhi_thread_hook_lock, NULL, UINET_LOCK_FILE, UINET_LOCK_LINE);
}


void
uhi_thread_set_name(const char *name)
{
	if (name != NULL) {
#if defined(__FreeBSD__)
		pthread_set_name_np(pthread_self(), name);
#elif defined(__linux__)
		pthread_setname_np(pthread_self(), name);
#endif
	}
}

int
uhi_tls_key_create(uhi_tls_key_t *key, void (*destructor)(void *))
{
	return (pthread_key_create((pthread_key_t *)key, destructor));
}


int
uhi_tls_key_delete(uhi_tls_key_t key)
{
	return (pthread_key_delete((pthread_key_t)key));
}


void *
uhi_tls_get(uhi_tls_key_t key)
{
	return (pthread_getspecific((pthread_key_t)key));
}


int
uhi_tls_set(uhi_tls_key_t key, void *data)
{
	return (pthread_setspecific((pthread_key_t)key, data));
}


uhi_thread_t
uhi_thread_self(void)
{
	return ((uhi_thread_t)pthread_self());
}


uint64_t
uhi_thread_self_id(void)
{
	return ((uint64_t)pthread_self());
}


void
uhi_thread_yield(void)
{
	sched_yield();
}


/*
 *  prio runs from 0 to 100, with 0 corresponding to the minimum possible
 *  priority and 100 corresponding to the maximum possible priority.
 */
int
uhi_thread_setprio(unsigned int prio)
{
	int policy;
	struct sched_param sparam;

	policy = SCHED_OTHER;
	sparam.sched_priority =
	    sched_get_priority_min(policy) +
	    ((sched_get_priority_max(policy) - sched_get_priority_min(policy)) * prio) / 100;

	return (pthread_setschedparam(pthread_self(), policy, &sparam));
}


/*
 *  prio runs from 0 to 100, with 0 corresponding to the minimum possible
 *  priority and 100 corresponding to the maximum possible priority.
 */
int
uhi_thread_setprio_rt(unsigned int prio)
{
	pthread_t t;
	int policy;
	struct sched_param sparam;

	t = pthread_self();

	policy = SCHED_RR;
	sparam.sched_priority =
	    sched_get_priority_min(policy) +
	    ((sched_get_priority_max(policy) - sched_get_priority_min(policy)) * prio) / 100;

	if (0 != pthread_setschedparam(t, policy, &sparam)) {
		policy = SCHED_FIFO;
		sparam.sched_priority =
		    sched_get_priority_min(policy) +
		    ((sched_get_priority_max(policy) - sched_get_priority_min(policy)) * prio) / 100;

	        return (pthread_setschedparam(t, policy, &sparam));
	}

	return (0);
}


int
uhi_cond_init(uhi_cond_t *c)
{
	pthread_condattr_t attr;
	pthread_cond_t *pc;
	int error;

	
	pc = malloc(sizeof(pthread_cond_t));
	if (NULL == pc)
		return (ENOMEM);

	*c = pc;

	pthread_condattr_init(&attr);

	error = pthread_cond_init(pc, &attr);
	pthread_condattr_destroy(&attr);

	return (error);
}


void
uhi_cond_destroy(uhi_cond_t *c)
{
	pthread_cond_t *pc;
	
	pc = (pthread_cond_t *)(*c);

	pthread_cond_destroy(pc);
	free(pc);
}


void
uhi_cond_wait(uhi_cond_t *c, uhi_mutex_t *m)
{
	pthread_cond_wait((pthread_cond_t *)(*c), (pthread_mutex_t *)(*m));
}


int
uhi_cond_timedwait(uhi_cond_t *c, uhi_mutex_t *m, uint64_t nsecs)
{
	struct timespec abstime;
	int64_t now_sec;
	long now_nsec;
	uint64_t total_nsec;

	uhi_clock_gettime(UHI_CLOCK_REALTIME, &now_sec, &now_nsec);

	abstime.tv_sec = now_sec + nsecs / UHI_NSEC_PER_SEC;
	total_nsec = now_nsec + nsecs % UHI_NSEC_PER_SEC;
	if (total_nsec >= UHI_NSEC_PER_SEC) {
		total_nsec -= UHI_NSEC_PER_SEC;
		abstime.tv_sec++;
	}
	abstime.tv_nsec = total_nsec;
	
	return (pthread_cond_timedwait((pthread_cond_t *)(*c), (pthread_mutex_t *)(*m), &abstime));
}


void
uhi_cond_signal(uhi_cond_t *c)
{
	pthread_cond_signal((pthread_cond_t *)(*c));
}


void
uhi_cond_broadcast(uhi_cond_t *c)
{
	pthread_cond_broadcast((pthread_cond_t *)(*c));
}


int
uhi_mutex_init(uhi_mutex_t *m, int opts)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t *pm;
	int error;

	pm = malloc(sizeof(pthread_mutex_t));
	if (NULL == pm)
		return (ENOMEM);

	*m = pm;

	pthread_mutexattr_init(&attr);

	if (opts & UHI_MTX_RECURSE) {
		if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) 
			printf("Warning: mtx will not be recursive\n");
	} else {
#if !defined(__APPLE__)
		if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP))
#endif /* __APPLE__ */
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
	}
	
	error = pthread_mutex_init(pm, &attr);
	pthread_mutexattr_destroy(&attr);	    

	return (error);
}


void
uhi_mutex_destroy(uhi_mutex_t *m)
{
	pthread_mutex_t *pm;
	
	pm = (pthread_mutex_t *)(*m);

	pthread_mutex_destroy(pm);
	free(pm);
}


void
_uhi_mutex_lock(uhi_mutex_t *m, void *l, const char *file, int line)
{
	uhi_lock_log("mtx", "lock", l, m, file, line);
	pthread_mutex_lock((pthread_mutex_t *)(*m));
}


/*
 * Returns 0 if the mutex cannot be acquired, non-zero if it can.
 */
int
_uhi_mutex_trylock(uhi_mutex_t *m, void *l, const char *file, int line)
{
	int ret;
	ret = (0 == pthread_mutex_trylock((pthread_mutex_t *)(*m)));
	if (ret)
		uhi_lock_log("mtx", "trylock", l, m, file, line);
	return (ret);
}


void
_uhi_mutex_unlock(uhi_mutex_t *m, void *l, const char *file, int line)
{
	uhi_lock_log("mtx", "unlock", l, m, file, line);
	pthread_mutex_unlock((pthread_mutex_t *)(*m));
}


int
uhi_rwlock_init(uhi_rwlock_t *rw, int opts)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t *pm;
	int error;
	
	pm = malloc(sizeof(pthread_mutex_t));
	if (NULL == pm)
		return (ENOMEM);

	*rw = pm;

	pthread_mutexattr_init(&attr);

	/* XXX
	 *
	 * An rwlock always allows recursive read locks and allows recursive
	 * write locks if UHI_RW_WRECURSE is specified.  pthread_mutex can
	 * either be recursive or not, so we always specify a recursive
	 * pthread_mutex in order to not break the always-read-recursive
	 * behavior of rwlocks.
	 *
	 * Note that pthread_rwlocks do not allow recursion, so aren't a
	 * contender for implementing the rwlock API.
	 *
	 */

	if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
		printf("Warning: rwlock will not be read recursive\n");
		if (opts & UHI_RW_WRECURSE)
			printf("Warning: rwlock will not be write recursive\n");
	}

	if (0 != pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)) {
		printf("Warning: priority will not propagate to rwlock holder\n");
	}

	error = pthread_mutex_init(pm, &attr);
	pthread_mutexattr_destroy(&attr);

	return (error);
}


void
uhi_rwlock_destroy(uhi_rwlock_t *rw)
{
	pthread_mutex_t *pm;
	
	pm = (pthread_mutex_t *)(*rw);

	pthread_mutex_destroy(pm);
	free(pm);
}


void
_uhi_rwlock_wlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	uhi_lock_log("rw", "wlock", l, rw, file, line);
	pthread_mutex_lock((pthread_mutex_t *)(*rw));
}


int
_uhi_rwlock_trywlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	int ret;

	ret = (0 == pthread_mutex_trylock((pthread_mutex_t *)(*rw)));
	if (ret)
		uhi_lock_log("rw", "trywlock", l, rw, file, line);
	return (ret);
}


void
_uhi_rwlock_wunlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	uhi_lock_log("rw", "wunlock", l, rw, file, line);
	pthread_mutex_unlock((pthread_mutex_t *)(*rw));
}


void
_uhi_rwlock_rlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	uhi_lock_log("rw", "rlock", l, rw, file, line);
	pthread_mutex_lock((pthread_mutex_t *)(*rw));
}


int
_uhi_rwlock_tryrlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	int ret;

	ret = (0 == pthread_mutex_trylock((pthread_mutex_t *)(*rw)));
	if (ret)
		uhi_lock_log("rw", "tryrlock", l, rw, file, line);
	return (ret);
}


void
_uhi_rwlock_runlock(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	uhi_lock_log("rw", "runlock", l, rw, file, line);
	pthread_mutex_unlock((pthread_mutex_t *)(*rw));
}


int
_uhi_rwlock_tryupgrade(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	/*
	 * Always succeeds as this implementation is always an exclusive
	 * lock
	 */
	uhi_lock_log("rw", "tryupgrade", l, rw, file, line);
	return (1);
}


void
_uhi_rwlock_downgrade(uhi_rwlock_t *rw, void *l, const char *file, int line)
{
	/* 
	 * Nothing to do here.  In this implementation, there is only one
	 * grade of this lock.
	 */
	uhi_lock_log("rw", "downgrade", l, rw, file, line);
}


int
uhi_get_ifaddr(const char *ifname, uint8_t *ethaddr)
{
	struct ifaddrs *ifa, *ifa_current;
	int af;
	int error;

	if (-1 == getifaddrs(&ifa)) {
		perror("getifaddrs failed");
		return (-1);
	}

#if defined(__FreeBSD__)
	af = AF_LINK;
#elif defined(__linux__)			
	af = AF_PACKET;
#else
#error  Add support for obtaining an interface MAC address to this platform.
#endif /* __FreeBSD__*/

	ifa_current = ifa;
	error = -1;
	while (NULL != ifa_current) {
		if ((0 == strcmp(ifa_current->ifa_name, ifname)) &&
		    (af == ifa_current->ifa_addr->sa_family) &&
		    (NULL != ifa_current->ifa_data)) {
			unsigned char *addr;

#if defined(__FreeBSD__)
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa_current->ifa_addr;
			addr = &sdl->sdl_data[sdl->sdl_nlen];
#elif defined(__linux__)			
			struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa_current->ifa_addr;
			addr = sll->sll_addr;
#else
#error  Add support for obtaining an interface MAC address to this platform.
#endif /* __FreeBSD__*/
			
			memcpy(ethaddr, addr, ETHER_ADDR_LEN);
			error = 0;
			break;
		}
		ifa_current = ifa_current->ifa_next;
	}

	freeifaddrs(ifa);

	return (error);
}


void
uhi_arc4rand(void *ptr, unsigned int len, int reseed)
{

#if !defined(__APPLE__)
	(void)reseed;

	/* XXX assuming that we don't have to manually seed this */

	RAND_pseudo_bytes(ptr, len);
#else
	if (reseed)
		arc4random_stir();

	arc4random_buf(ptr, len);
#endif
}


uint32_t
uhi_arc4random(void)
{
        uint32_t ret;

        uhi_arc4rand(&ret, sizeof ret, 0);
        return ret;
}


static void
uhi_cleanup_handler(int signo, siginfo_t *info, void *uap)
{
	uinet_shutdown(signo);
	kill(getpid(), signo);
}


static void
uhi_install_cleanup_handler(int signo)
{
	struct sigaction sa;

	sigaction(signo, NULL, &sa);
	if (sa.sa_handler == SIG_DFL) {
		sa.sa_sigaction = uhi_cleanup_handler;
		sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
		sigfillset(&sa.sa_mask);
		sigaction(signo, &sa, NULL);
	}
}


/*
 * Install a cleanup handler for all catchable signals that by default will
 * terminate the process and that are currently set to the default handler.
 */
void
uhi_install_sighandlers(void)
{
	int i;
	int signal_list[] = {
		SIGHUP,
		SIGINT,
		SIGQUIT,
		SIGILL,
		SIGTRAP,
		SIGABRT,
#if !defined(__linux__)
		SIGEMT,
#endif
		SIGFPE,
		SIGBUS,
		SIGSEGV,
		SIGSYS,
		SIGPIPE,
		SIGALRM,
		SIGTERM,
		SIGXCPU,
		SIGXFSZ,
		SIGVTALRM,
		SIGPROF,
		SIGUSR1,
		SIGUSR2
	};

	for (i = 0; i < sizeof(signal_list)/sizeof(signal_list[0]); i++)
		uhi_install_cleanup_handler(signal_list[i]);
}


void
uhi_mask_all_signals(void)
{
	sigset_t sigs;

	sigfillset(&sigs);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}


void
uhi_unmask_all_signals(void)
{
	sigset_t sigs;

	sigemptyset(&sigs);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}


/*
 * The uhi_msg_* functions implement a simple fixed-size message + response
 * synchronization facility with the following properties:
 *
 *   - Safe to use in threads and signal handlers
 *   - Zero-size messages and/or responses are permitted
 */

int
uhi_msg_init(struct uhi_msg *msg, unsigned int size, unsigned int rsp_size)
{
	if (-1 == socketpair(PF_LOCAL, SOCK_STREAM, 0, msg->fds))
		return (1);

	msg->size = size ? size : 1;
	msg->rsp_size = rsp_size ? rsp_size : 1;

	return (0);
}


void
uhi_msg_destroy(struct uhi_msg *msg)
{
	int old_errno = errno;

	close(msg->fds[0]);
	close(msg->fds[1]);

	errno = old_errno;
}


static int
uhi_msg_sock_write(int fd, void *payload, unsigned int size)
{
	uint8_t dummy = 0;
	unsigned int write_size;
	int result;
	int old_errno = errno;

	write_size = payload ? size : 1;
	if (write_size == write(fd, payload ? payload : &dummy,
				write_size))
		result = 0;
	else
		result = 1;

	errno = old_errno;
	
	return (result);
}


static int
uhi_msg_sock_read(int fd, void *payload, unsigned int size)
{
	uint8_t dummy = 0;
	unsigned int read_size;
	int result;
	int old_errno = errno;

	read_size = payload ? size : 1;
	if (read_size == read(fd, payload ? payload : &dummy,
			      read_size))
		result = 0;
	else
		result = 1;

	errno = old_errno;
	
	return (result);
}


int
uhi_msg_send(struct uhi_msg *msg, void *payload)
{
	return (uhi_msg_sock_write(msg->fds[0], payload, msg->size));
}


int
uhi_msg_wait(struct uhi_msg *msg, void *payload)
{
	return (uhi_msg_sock_read(msg->fds[1], payload, msg->size));
}


int
uhi_msg_rsp_send(struct uhi_msg *msg, void *payload)
{
	return (uhi_msg_sock_write(msg->fds[1], payload, msg->rsp_size));
}


int
uhi_msg_rsp_wait(struct uhi_msg *msg, void *payload)
{
	return (uhi_msg_sock_read(msg->fds[0], payload, msg->rsp_size));
}

int
uhi_get_stacktrace(uintptr_t *pcs, int npcs)
{
#if defined(UINET_STACK_UNWIND)
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip, sp;
	int i = 0;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	while (unw_step(&cursor) > 0 && i < npcs) {
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);
		pcs[i] = (uintptr_t) ip;
//		printf ("ip = %lx, sp = %lx\n", (long) ip, (long) sp);
		i++;
	}
	return (i);
#else
	return (0);
#endif
}
