#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include "memstat.h"

void
domemstat_zone(void)
{
	struct memory_type_list *mtlp;
	struct memory_type *mtp;
	char name[MEMTYPE_MAXNAME + 1];
	int error;

	mtlp = memstat_mtl_alloc();
	if (mtlp == NULL) {
		warn("memstat_mtl_alloc");
		return;
	}
	if (memstat_sysctl_uma(mtlp, 0) < 0) {
		warnx("memstat_sysctl_uma: %s",
		    memstat_strerror(memstat_mtl_geterror(mtlp)));
		return;
	}

	printf("%-20s %6s %6s %8s %8s %8s %4s %4s\n\n", "ITEM", "SIZE",
	    "LIMIT", "USED", "FREE", "REQ", "FAIL", "SLEEP");
	for (mtp = memstat_mtl_first(mtlp); mtp != NULL;
	    mtp = memstat_mtl_next(mtp)) {
		strlcpy(name, memstat_get_name(mtp), MEMTYPE_MAXNAME);
		strcat(name, ":");
		printf("%-20s %6llu, %6llu,%8llu,%8llu,%8llu,%4llu,%4llu\n",
		    name,
		    (unsigned long long) memstat_get_size(mtp),
		    (unsigned long long) memstat_get_countlimit(mtp),
		    (unsigned long long) memstat_get_count(mtp),
		    (unsigned long long) memstat_get_free(mtp),
		    (unsigned long long) memstat_get_numallocs(mtp),
		    (unsigned long long) memstat_get_failures(mtp),
		    (unsigned long long) memstat_get_sleeps(mtp));
	}
	memstat_mtl_free(mtlp);
	printf("\n");
}
