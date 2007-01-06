#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int file_open (char* name, int mode) {
	int fd;
	int err = 0;

	if (!name)
		return -EINVAL;
	fd = open((char*)name,mode|O_CREAT|O_EXCL,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if (fd < 0)
		err = errno;
	return (fd < 0)? -err: fd;
}


int pipe_open (const char* command, char** args, int mode, pid_t* pid) {
	int err = 0;
	int fds[2] = { -1, -1 };
#define PIPE_FD_READ  fds[0]
#define PIPE_FD_WRITE fds[1]
	int w;
	pid_t p;

	if (mode == O_RDONLY)
		w = 0;
	else if (mode == O_WRONLY)
		w = 1;
	else
		return -EINVAL;

	if (pipe(fds) == -1)
		return -errno;

	p = fork();
	switch(p) {
	case -1:
		err = errno;
		close(fds[0]);
		close(fds[1]);
		return -err;

	case 0: /* child */
		if (w) { /* keep read open */
			close(PIPE_FD_WRITE);
			if (PIPE_FD_READ != STDIN_FILENO) {
				if (dup2(PIPE_FD_READ,STDIN_FILENO) < 0) {
					perror("dup2");
					exit(EXIT_FAILURE);
				}
				close(PIPE_FD_READ);
			}
		} else { /* keep write open */
			close(PIPE_FD_READ);
			if (PIPE_FD_WRITE != STDOUT_FILENO) {
				if (dup2(PIPE_FD_WRITE,STDOUT_FILENO) < 0) {
					perror("dup2");
					exit(EXIT_FAILURE);
				}
				close(PIPE_FD_WRITE);
			}
		}
		execvp(command,args);
		perror("execvp");
		exit(EXIT_FAILURE);
		
	default: /* parent */
		if (*pid)
			*pid = p;
		if (w) {
			close(PIPE_FD_READ);
			return PIPE_FD_WRITE;
		} else {
			close(PIPE_FD_WRITE);
			return PIPE_FD_READ;
		}
	}
}
