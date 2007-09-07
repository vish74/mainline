#include "md5.h"

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
	uint8_t n[16];
	int status;
	if (fd < 0)
		return -errno;
	status = (int)read(fd, n, sizeof(n));
	if (status < 0)
		return -errno;
	if (status == 0)
		return -EIO;
	MD5(nonce, n, (size_t)status);
	(void)close(fd);
	return 0;
}
