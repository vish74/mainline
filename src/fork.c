#include <signal.h>

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

int obexpushd_create_instance (void* (*cb)(void*), void *cbdata) {
	pid_t p = fork();
	switch (p) {
	case 0:
		(void)signal(SIGCHLD, SIG_DFL);
		(void)signal(SIGINT, SIG_DFL);
		(void)signal(SIGTERM, SIG_DFL);
		(void)cb(cbdata);
		exit(EXIT_SUCCESS);

	case -1:
		return -errno;
	}

	return 0;
}

static void obexpushd_wait (int sig) {
	/* pid_t pidOfChild; */
	int status;
	if (sig != SIGCLD)
		return;

	/* pidOfChild = */wait(&status);
	if (WIFEXITED(status))
		fprintf(stderr, "child exited with exit code %d\n", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		fprintf(stderr, "child got signal %d\n", WTERMSIG(status));
}

int obexpushd_start (struct net_data *data, unsigned int count) {
	unsigned int i;
	(void)signal(SIGCHLD, obexpushd_wait);

#if defined(USE_LIBGCRYPT)
	(void)gcry_check_version(NULL);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

	/* initialize all enabled listeners */
	for (i = 0; i < count; ++i) {
		int fd = -1;
		if (!data[i].handler)
			continue;
		net_init(&data[i], eventcb);
		if (!data[i].obex)
			exit(EXIT_FAILURE);
		fd = OBEX_GetFD(data[i].obex);
		if (fd == -1) {
			perror("OBEX_GetFD()");
			exit(EXIT_FAILURE);
		}
	}
	
	/* run the multiplexer */
	do {
		int topfd = 0;
		fd_set fds;
		FD_ZERO(&fds);
		for (i = 0; i < count; ++i) {
			if (!data[i].handler)
				continue;
			if (data[i].obex) {
				int fd = OBEX_GetFD(data[i].obex);
				if (fd == -1) {
					perror("OBEX_GetFD()");
					exit(EXIT_FAILURE);
				}
				if (fd > topfd)
					topfd = fd;
				FD_SET(fd, &fds);
			}
		}
		select(topfd+1, &fds, NULL, NULL, NULL);
		for (i = 0; i < count; ++i) {
			int fd = -1;
			if (!data[i].handler)
				continue;
			if (!data[i].obex)
				continue;
			fd = net_get_listen_fd(&data[i]);
			if (FD_ISSET(fd,&fds)) {
				if (OBEX_HandleInput(data[i].obex,1) < 0) {
					if (net_get_life_status(&data[i]) == LIFE_STATUS_DEAD) {
						net_cleanup(&data[i]);
						break;
					}
				}
			}
		}			
	} while (1);
}
