
#include <stdio.h>
#include <inttypes.h>

struct io_internal_data {
	char *basedir;

	FILE *in;
	FILE *out;
};

char* io_internal_get_fullname(const char *basedir, const char *subdir,
			       const uint16_t *filename);
