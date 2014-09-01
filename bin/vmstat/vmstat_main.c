
#include <stdio.h>
#include <stdlib.h>

extern int domemstat_zone();
extern int domemstat_malloc();

int
main(int argc, const char *argv[])
{

	/* libuinet doesn't track malloc statistics at the moment */
	//domemstat_malloc();
	domemstat_zone();
}
