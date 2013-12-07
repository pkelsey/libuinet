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

#undef _KERNEL
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/cpuset.h>
#include <sys/mman.h>

#include "uinet_host_interface.h"


#if defined(UINET_PROFILE)
#include <sys/time.h>

static struct itimerval prof_itimer;
#endif /* UINET_PROFILE */

static pthread_key_t curthread_key;


void
uhi_init(void)
{
	int error;

	/*
	 * We don't translate these in our poll wrapper.
	 */
	assert(UHI_POLLIN == POLLIN);
	assert(UHI_POLLPRI == POLLPRI);
	assert(UHI_POLLOUT == POLLOUT);
	assert(UHI_POLLERR == POLLERR);
	assert(UHI_POLLHUP == POLLHUP);
	assert(UHI_POLLNVAL == POLLNVAL);
	
	error = pthread_key_create(&curthread_key, NULL);
	if (error != 0)
		printf("Warning: unable to create pthread key for curthread data (%d)\n", error);

#if defined(UINET_PROFILE)
	printf("getting prof timer\n");
	getitimer(ITIMER_PROF, &prof_itimer);
#endif /* UINET_PROFILE */

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
	return (realloc(p, size));
}


void *
uhi_reallocf(void *p, uint64_t size)
{
	return (reallocf(p, size));
}


void
uhi_free(void *p)
{
	free(p);
}


void
uhi_clock_gettime(int id, int64_t *sec, long *nsec)
{
	struct timespec ts;
	int host_id;
	int rv;

	switch (id) {
	case UHI_CLOCK_REALTIME:
		host_id = CLOCK_REALTIME;
		break;
	case UHI_CLOCK_MONOTONIC:
	default:
		host_id = CLOCK_MONOTONIC;
		break;
	}

	rv = clock_gettime(host_id, &ts);
	assert(0 == rv);

	*sec = (int64_t)ts.tv_sec;
	*nsec = (long)ts.tv_nsec;
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

	ts.tv_sec = nsecs / (1000UL*1000UL*1000UL);
	ts.tv_nsec = nsecs % (1000UL*1000UL*1000UL);
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
	if ((flags & UHI_MAP_NOCORE) == UHI_MAP_NOCORE)   host_flags |= MAP_NOCORE;

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
	cpuset_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpuset);
}


static void *
pthread_start_routine(void *arg)
{
	struct uhi_thread_start_args *tsa = arg;
	int error;

#if defined(UINET_PROFILE)
	setitimer(ITIMER_PROF, &prof_itimer, NULL);
#endif /* UINET_PROFILE */

	error = pthread_setspecific(curthread_key, tsa->thread_specific_data);
	if (error != 0)
		printf("Warning: unable to set thread-specific data (%d)\n", error);

	if (tsa->host_thread_id) {
		/*
		 *  The cast below is technically a danger, but should work
		 *  in practice as pthread_t is typically a pointer or a
		 *  long, and it's unlikely there's a platform where a long
		 *  won't fit in the storage of a void *.
		 */
		assert(sizeof(uhi_thread_t) >= sizeof(pthread_t));
		*tsa->host_thread_id = (uhi_thread_t)pthread_self();
	}

	pthread_set_name_np(pthread_self(), tsa->name);

	tsa->start_routine(tsa->start_routine_arg);
	tsa->end_routine(tsa);
	free(tsa->thread_specific_data);
	free(tsa);

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

	if (new_thread)
		*new_thread = (uhi_thread_t)thread;

	return (error);
	
}


void
uhi_thread_exit(void)
{
	pthread_exit(NULL);
}


void *
uhi_thread_get_thread_specific_data(void)
{
	return (pthread_getspecific(curthread_key));
}


int
uhi_thread_set_thread_specific_data(void *data)
{
	return (pthread_setspecific(curthread_key, data));
}


uhi_thread_t
uhi_thread_self(void)
{
	return ((uhi_thread_t)pthread_self());
}


void
uhi_thread_yield(void)
{
	pthread_yield();
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
    
	
	pc = malloc(sizeof(pthread_cond_t));
	if (NULL == pc)
		return (ENOMEM);

	*c = pc;

	pthread_condattr_init(&attr);
	if (0 != pthread_condattr_setclock(&attr, CLOCK_MONOTONIC))
		printf("Warning: condition variable timed wait using CLOCK_REALTIME");

	return (pthread_cond_init(pc, &attr));
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

	abstime.tv_sec = nsecs / (1000UL*1000UL*1000UL);
	abstime.tv_nsec = nsecs % (1000UL*1000UL*1000UL);

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
	
	pm = malloc(sizeof(pthread_mutex_t));
	if (NULL == pm)
		return (ENOMEM);

	*m = pm;

	pthread_mutexattr_init(&attr);

	if (opts & UHI_MTX_RECURSE) {
		if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) 
			printf("Warning: mtx will not be recursive\n");
	} else {
		if (0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP))
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
	}

	return (pthread_mutex_init(pm, &attr));
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
uhi_mutex_lock(uhi_mutex_t *m)
{
	pthread_mutex_lock((pthread_mutex_t *)(*m));
}


/*
 * Returns 0 if the mutex cannot be acquired, non-zero if it can.
 */
int
uhi_mutex_trylock(uhi_mutex_t *m)
{
	return (0 == pthread_mutex_trylock((pthread_mutex_t *)(*m)));
}


void
uhi_mutex_unlock(uhi_mutex_t *m)
{
	pthread_mutex_unlock((pthread_mutex_t *)(*m));
}


int
uhi_rwlock_init(uhi_rwlock_t *rw, int opts)
{
	pthread_mutexattr_t attr;
	pthread_mutex_t *pm;
	
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

	return(pthread_mutex_init(pm, &attr));
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
uhi_rwlock_wlock(uhi_rwlock_t *rw)
{
	pthread_mutex_lock((pthread_mutex_t *)(*rw));
}


int
uhi_rwlock_trywlock(uhi_rwlock_t *rw)
{
	return (0 == pthread_mutex_trylock((pthread_mutex_t *)(*rw)));
}


void
uhi_rwlock_wunlock(uhi_rwlock_t *rw)
{
	pthread_mutex_unlock((pthread_mutex_t *)(*rw));
}


void
uhi_rwlock_rlock(uhi_rwlock_t *rw)
{
	pthread_mutex_lock((pthread_mutex_t *)(*rw));
}


int
uhi_rwlock_tryrlock(uhi_rwlock_t *rw)
{
	return (0 == pthread_mutex_trylock((pthread_mutex_t *)(*rw)));
}


void
uhi_rwlock_runlock(uhi_rwlock_t *rw)
{
	pthread_mutex_unlock((pthread_mutex_t *)(*rw));
}


int
uhi_rwlock_tryupgrade(uhi_rwlock_t *rw)
{
	/*
	 * Always succeeds as this implementation is always an exlcusive
	 * lock
	 */
	return (0);
}


void
uhi_rwlock_downgrade(uhi_rwlock_t *rw)
{
	/* 
	 * Nothing to do here.  In this implementation, there is only one
	 * grade of this lock.
	 */
}


