/* Copyright (C) 2006-2007 Hendrik Sattler <post@hendrik-sattler.de>
 *       
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.		       
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *	       
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

/* work around crappy GNU libc to define environ in unistd.h as
 * define in environ(3posix)
 */
#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(USE_SPAWN)
#include <spawn.h>
#endif

void pipe_close (int client_fds[2])
{
	if (client_fds) {
		close(client_fds[0]);
		close(client_fds[1]);
	}		
}

int pipe_open (
	const char* command,
	char** args,
	int client_fds[2],
	pid_t *pid
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

#if defined(USE_SPAWN)
	/* In theory, using spawn() is more efficient that fork()+exec().
	 */
	posix_spawn_file_actions_t actions;
	if (posix_spawn_file_actions_init(&actions) ||
	    posix_spawn_file_actions_addclose(&actions, PIPE_SERVER_WRITE) ||
	    posix_spawn_file_actions_addclose(&actions, PIPE_SERVER_READ) ||
	    posix_spawn_file_actions_adddup2(&actions, PIPE_CLIENT_STDIN, STDIN_FILENO) ||
	    posix_spawn_file_actions_adddup2(&actions, PIPE_CLIENT_STDOUT, STDOUT_FILENO) ||
	    posix_spawnp(&p, command, &actions, NULL, args, environ) ||
	    posix_spawn_file_actions_destroy(&actions))
	{
#else
	p = fork();
	if (p == 0) {
		/* child */
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

	} else if (p == -1) {
#endif		
		err = errno;
		pipe_close(fds[0]);
		pipe_close(fds[1]);
		return -err;
	}
	/* parent */
	close(PIPE_CLIENT_STDIN);
	close(PIPE_CLIENT_STDOUT);
	if (client_fds) {
		client_fds[0] = PIPE_SERVER_READ;
		client_fds[1] = PIPE_SERVER_WRITE;
	}
	
	if (pid)
		*pid = p;
	return 0;
}
