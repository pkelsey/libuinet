#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include "memstat.h"

void
domemstat_malloc(void)
{
	struct memory_type_list *mtlp;
	struct memory_type *mtp;
	int error, first, i;

	mtlp = memstat_mtl_alloc();
	if (mtlp == NULL) {
		warn("memstat_mtl_alloc");
		return;
	}
	if (memstat_sysctl_malloc(mtlp, 0) < 0) {
		warnx("memstat_sysctl_malloc: %s",
		    memstat_strerror(memstat_mtl_geterror(mtlp)));
		return;
	}
	printf("%13s %5s %6s %7s %8s  Size(s)\n", "Type", "InUse", "MemUse",
	    "HighUse", "Requests");
	for (mtp = memstat_mtl_first(mtlp); mtp != NULL;
	    mtp = memstat_mtl_next(mtp)) {
		if (memstat_get_numallocs(mtp) == 0 &&
		    memstat_get_count(mtp) == 0)
			continue;
		printf("%13s %5llu %5llu K %7s %8llu  ",
		    memstat_get_name(mtp),
		    (unsigned long long) memstat_get_count(mtp),
		    (unsigned long long) (memstat_get_bytes(mtp) + 1023) / 1024, "-",
		    (unsigned long long) memstat_get_numallocs(mtp));
		first = 1;
		for (i = 0; i < 32; i++) {
			if (memstat_get_sizemask(mtp) & (1 << i)) {
				if (!first)
					printf(",");
				printf("%d", 1 << (i + 4));
				first = 0;
			}
		}
		printf("\n");
	}
	memstat_mtl_free(mtlp);
}
