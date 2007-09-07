#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int file_open (
	char* name,
	int mode
)
{
	int fd;
	int err = 0;

	if (!name)
		return -EINVAL;
	fd = open((char*)name, mode|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if (fd < 0)
		err = errno;
	return (fd < 0)? -err: fd;
}

void pipe_close (int client_fds[2])
{
	if (client_fds) {
		close(client_fds[0]);
		close(client_fds[1]);
	}		
}

pid_t pipe_open (
	const char* command,
	char** args, 
	int client_fds[2]
)
{
	int fds[2][2] = {{ -1, -1 }, {-1, -1}};
#define PIPE_CLIENT_STDIN  fds[0][0]
#define PIPE_SERVER_WRITE  fds[0][1]
#define PIPE_SERVER_READ   fds[1][0]
#define PIPE_CLIENT_STDOUT fds[1][1]

	int err = 0;
	pid_t p;

	if (pipe(fds[0]) == -1)
		return -errno;

	if (pipe(fds[1]) == -1) {
		err = errno;
		pipe_close(fds[0]);
		return -err;
	}

	p = fork();
	switch(p) {
	case -1:
		err = errno;
		pipe_close(fds[0]);
		pipe_close(fds[1]);
		return -err;

	case 0: /* child */
		close(PIPE_SERVER_WRITE);
		close(PIPE_SERVER_READ);
		if (PIPE_CLIENT_STDIN != STDIN_FILENO) {
			if (dup2(PIPE_CLIENT_STDIN, STDIN_FILENO) < 0) {
				perror("dup2");
				exit(EXIT_FAILURE);
			}
			close(PIPE_CLIENT_STDIN);
		}
		if (PIPE_CLIENT_STDOUT != STDOUT_FILENO) {
			if (dup2(PIPE_CLIENT_STDOUT, STDOUT_FILENO) < 0) {
				perror("dup2");
				exit(EXIT_FAILURE);
			}
			close(PIPE_CLIENT_STDOUT);
		}
		execvp(command, args);
		perror("execvp");
		exit(EXIT_FAILURE);
		
	default: /* parent */
		close(PIPE_CLIENT_STDIN);
		close(PIPE_CLIENT_STDOUT);
		if (client_fds) {
			client_fds[0] = PIPE_SERVER_READ;
			client_fds[1] = PIPE_SERVER_WRITE;
		}
		return p;
	}
}
