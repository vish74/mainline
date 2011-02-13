#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define set_closexec_flag(fd) fcntl(fd, F_SETFD, FD_CLOEXEC)

static inline int open_closexec(const char *pathname, int flags, mode_t mode) {
	int err = open(pathname, (flags | O_CLOEXEC), mode);

#if ! O_CLOEXEC
	if (err != -1)
		(void)set_closexec_flag(err);
#endif

	return err;
}

static inline int pipe_closexec(int pipefd[2]) {
#if O_CLOEXEC
	return pipe2(pipefd, O_CLOEXEC);
#else
	int err = pipe(pipefd);
	if (err != -1) {
		(void)set_closexec_flag(pipefd[0]);
		(void)set_closexec_flag(pipefd[1]);
	}
	return err;
#endif
}
