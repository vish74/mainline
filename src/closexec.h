#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static inline int open_closexec(const char *pathname, int flags, mode_t mode) {
	int err = open(pathname, (flags | O_CLOEXEC), mode);

#if ! O_CLOEXEC
	if (err != -1)
		(void)fcntl(err, F_SETFD, FD_CLOEXEC);
#endif

	return err;
}

static inline int pipe_closexec(int pipefd[2]) {
#if O_CLOEXEC
	return pipe2(pipefd, O_CLOEXEC);
#else
	int err = pipe(pipefd);
	if (err != -1) {
		(void)fcntrl(pipefd[0], F_SETFD, FD_CLOEXEC);
		(void)fcntrl(pipefd[1], F_SETFD, FD_CLOEXEC);
	}
	return err;
#endif
}
