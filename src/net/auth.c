#include "core.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define RANDOM_FILE "/dev/urandom"
int get_nonce (
	/*@out@*/ uint8_t nonce[16]
)
{
	int fd = open(RANDOM_FILE, O_RDONLY);
	int status;
	if (fd < 0)
		return -errno;
	status = (int)read(fd, nonce, 16);
	if (status < 0)
		return -errno;
	if (status != 16)
		return -EIO;
	(void)close(fd);
	return 0;
}
