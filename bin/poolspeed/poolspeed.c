
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "uinet_api.h"

/* 
 * pthread_barrier_t is not implemented on some platforms, so roll one that
 * will work everywhere.
 */
struct barrier {
	int target;
	int count;
	pthread_cond_t cv;
	pthread_mutex_t mtx;
};


struct test_params {
	int id;
	int use_malloc;
	int alloc_size;
	int num_allocs;
	int touch;
	uinet_pool_t pool;
	pthread_t thread;
	struct barrier *barrier;
};


static int
barrier_init(struct barrier *barrier, int target)
{
	if (target < 1)
		return (1);

	barrier->target = target;
	barrier->count = 0;

	if (pthread_cond_init(&barrier->cv, NULL))
		return (1);

	if (pthread_mutex_init(&barrier->mtx, NULL)) {
		pthread_cond_destroy(&barrier->cv);
		return (1);
	}
	
	return (0);
}


static void
barrier_destroy(struct barrier *barrier)
{
	pthread_mutex_destroy(&barrier->mtx);
	pthread_cond_destroy(&barrier->cv);
}

static void
barrier_wait(struct barrier *barrier)
{
	pthread_mutex_lock(&barrier->mtx);
	barrier->count++;
	if (barrier->count == barrier->target) {
		barrier->count = 0;
		pthread_cond_broadcast(&barrier->cv);
	} else {
		do { 
			pthread_cond_wait(&barrier->cv, &barrier->mtx);
		} while (barrier->count != 0);
	}
	pthread_mutex_unlock(&barrier->mtx);
}


static void
do_test(const struct test_params *params)
{
	int i;
	volatile char *p;
	
	if (params->use_malloc) {
		for (i = 0; i < params->num_allocs; i++) {
			p = malloc(params->alloc_size);
			if (p == NULL) {
				printf("Thread %d: alllocation %d failed\n", params->id, i);
				break;
			}
			if (params->touch)
				*p = 1;
		}
	} else {
		for (i = 0; i < params->num_allocs; i++) {
			p = uinet_pool_alloc(params->pool, 0);
			if (p == NULL) {
				printf("Thrad %d: allocation %d failed\n", params->id, i);
				break;
			}
			if (params->touch)
				*p = 1;
		}
	}
}


static void *
start_test_thread(void *arg)
{
	const struct test_params *params = arg;

	if (!params->use_malloc)
		uinet_initialize_thread();

	printf("Thread %d: count=%d\n", params->id, params->num_allocs);
	barrier_wait(params->barrier);

	do_test(arg);
	return (NULL);
}


int main(int argc, char **argv)
{
	int alloc_size = 100;
	int num_allocs = 1000 * 1000;
	int pool_size = 1000 * 1000;
	int use_malloc = 0;
	int touch = 0;
	int warm = 0;
	int concurrency = 1;
	uinet_pool_t pool;
	int i;
	struct timespec t1, t2;
	char ch;
	void **allocations;
	struct test_params *params;
	struct barrier barrier;
	int allocs_per_thread;
	int remainder;

	while ((ch = getopt(argc, argv, "c:mn:p:s:tw")) != -1) {
		switch (ch) {
		case 'c':
			concurrency = atoi(optarg);
			if (concurrency < 1)
				concurrency = 1;
			break;
		case 'm':
			use_malloc = 1;
			break;
		case 'n':
			num_allocs = atoi(optarg);
			if (num_allocs < 1)
				num_allocs = 1;
			break;
		case 'p':
			pool_size = atoi(optarg);
			if (pool_size < 1)
				pool_size = 1;
			break;
		case 's':
			alloc_size = atoi(optarg);
			if (alloc_size < 1)
				alloc_size = 1;
			break;
		case 't':
			touch = 1;
			break;
		case 'w':
			warm = 1;
			break;
		default:
			printf("Unknown option \"%c\"\n", ch);
			return (1);
		}
	}
	argc -= optind;
	argv += optind;

	params = malloc(sizeof(struct test_params) * concurrency);
	if (params == NULL) {
		printf("Failed to allocate params array\n");
		return (1);
	}

	if (!use_malloc) {
		uinet_init(1, 128*1024, 0);

		pool = uinet_pool_create("test pool", alloc_size, NULL, NULL, NULL, NULL, UINET_POOL_ALIGN_PTR, 0);
		if (NULL == pool) {
			printf("Pool creation failed\n");
			return (1);
		}
		uinet_pool_set_max(pool, pool_size);
	}

	clock_getres(CLOCK_PROF, &t1);
	printf("Timing resolution is %ldns\n", t1.tv_nsec);

	if (barrier_init(&barrier, concurrency)) {
		printf("Failed to initialize thread sync barrier\n");
		return (1);
	}

	printf("Test plan: threads=%d size=%d count=%d warmup=%s\n",
	       concurrency, alloc_size, num_allocs, warm ? "yes" : "no");

	allocs_per_thread = num_allocs / concurrency;
	remainder = num_allocs % concurrency;
	printf("Thread 0: count=%d\n", allocs_per_thread);
	for (i = 0; i < concurrency; i++) {
		params[i].id = i;
		params[i].use_malloc = use_malloc;
		params[i].alloc_size = alloc_size;
		params[i].num_allocs = allocs_per_thread;
		if (remainder) {
			params[i].num_allocs++;
			remainder--;
		}
		params[i].touch = touch;
		params[i].pool = pool;
		params[i].barrier = &barrier;
		
		if (i > 0)
			if (pthread_create(&params[i].thread, NULL, start_test_thread, &params[i])) {
				printf("Failed to create thread %d\n", i);
				return (1);
			}
	}

	if (warm) {
		allocations = malloc(sizeof(void *) * num_allocs);
		if (allocations == NULL) {
			printf("Failed to allocate results array\n");
			return (1);
		}

		if (use_malloc) {
			for (i = 0; i < num_allocs; i++) {
				allocations[i] = malloc(alloc_size);
				if (allocations[i] == NULL) {
					printf("Alllocation %d failed during warmup\n", i);
					return (1);
				}
			}
			for (i = 0; i < num_allocs; i++) {
				free(allocations[i]);
			}
		} else {
			for (i = 0; i < num_allocs; i++) {
				allocations[i] = uinet_pool_alloc(pool, 0);
				if (allocations[i] == NULL) {
					printf("Alllocation %d failed during warmup\n", i);
					return (1);
				}
			}
			for (i = 0; i < num_allocs; i++) {
				uinet_pool_free(pool, allocations[i]);
			}
		}
	}

	barrier_wait(params[0].barrier);

	clock_gettime(CLOCK_PROF, &t1);
	
	do_test(&params[0]);

	for (i = 1; i < concurrency; i++)
		pthread_join(params[i].thread, NULL);

	clock_gettime(CLOCK_PROF, &t2);

	if (t1.tv_nsec > t2.tv_nsec) {
		t2.tv_nsec = 1000000000 + t2.tv_nsec - t1.tv_nsec;
		t2.tv_sec = t2.tv_sec - t1.tv_sec - 1;
	} else {
		t2.tv_nsec = t2.tv_nsec - t1.tv_nsec;
		t2.tv_sec = t2.tv_sec - t1.tv_sec;
	}
	printf("Time for %d allocations of %d bytes was %lds %ld.%03ldms\n",
	       num_allocs, alloc_size, t2.tv_sec, t2.tv_nsec / 1000000, (t2.tv_nsec % 1000000) / 1000);

	barrier_destroy(&barrier);
	if (!use_malloc) {
		uinet_pool_destroy(pool);
		uinet_shutdown(0);
	}
	if (warm)
		free(allocations);

	free(params);


	return (0);
}
