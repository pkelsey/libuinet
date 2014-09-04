
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "uinet_api.h"



int main(int argc, char **argv)
{
	int alloc_size = 100;
	int num_allocs = 1000 * 1000;
	int pool_size = 1000 * 1000;
	int do_malloc = 0;
	int touch = 0;
	int warm = 0;
	uinet_pool_t pool;
	int i;
	struct timespec t1, t2;
	char ch;
	volatile int *p;
	void **allocations;

	while ((ch = getopt(argc, argv, "mn:p:s:tw")) != -1) {
		switch (ch) {
		case 'm':
			do_malloc = 1;
			break;
		case 'n':
			num_allocs = atoi(optarg);
			break;
		case 'p':
			pool_size = atoi(optarg);
			break;
		case 's':
			alloc_size = atoi(optarg);
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

	if (warm) {
		allocations = malloc(sizeof(void *) * num_allocs);
		if (allocations == NULL) {
			printf("Failed to allocate results array\n");
			return (1);
		}
	}

	clock_getres(CLOCK_PROF, &t1);
	printf("Timing resolution is %ldns\n", t1.tv_nsec);
	printf("Performing %d allocations of %d bytes %s\n", num_allocs, alloc_size, warm ? "after warming up" : "");

	if (do_malloc) {
		if (warm) {
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
		}

		clock_gettime(CLOCK_PROF, &t1);
		for (i = 0; i < num_allocs; i++) {
			p = malloc(alloc_size);
			if (p == NULL) {
				printf("Alllocation %d failed\n", i);
				break;
			}
			if (touch)
				*p = 1;
		}
		clock_gettime(CLOCK_PROF, &t2);
	} else {
		uinet_init(1, 128*1024, 0);

		pool = uinet_pool_create("test pool", alloc_size, NULL, NULL, NULL, NULL, UINET_POOL_ALIGN_PTR, 0);
		if (NULL == pool) {
			printf("Pool creation failed\n");
			return (1);
		}
		uinet_pool_set_max(pool, pool_size);

		if (warm) {
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

		clock_gettime(CLOCK_PROF, &t1);
		for (i = 0; i < num_allocs; i++) {
			p = uinet_pool_alloc(pool, 0);
			if (p == NULL) {
				printf("Allocation %d failed\n", i);
				break;
			}
			if (touch)
				*p = 1;
		}
		clock_gettime(CLOCK_PROF, &t2);

#if 0
		uinet_pool_destroy(pool);

		uinet_shutdown(0);
#endif
	}


	if (t1.tv_nsec > t2.tv_nsec) {
		t2.tv_nsec = 1000000000 + t2.tv_nsec - t1.tv_nsec;
		t2.tv_sec = t2.tv_sec - t1.tv_sec - 1;
	} else {
		t2.tv_nsec = t2.tv_nsec - t1.tv_nsec;
		t2.tv_sec = t2.tv_sec - t1.tv_sec;
	}
	printf("Time for %d allocations of %d bytes was %lds %ld.%03ldms\n",
	       num_allocs, alloc_size, t2.tv_sec, t2.tv_nsec / 1000000, (t2.tv_nsec % 1000000) / 1000);


	return (0);
}
