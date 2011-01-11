#include "fdobex.h"

#include <unistd.h>
#include <fcntl.h>

#include "compiler.h"

static
int fdobex_ctrans_listen(obex_t __unused *handle, void * customdata)
{
	struct fdobex_args *args = customdata;

#if HAS_SIGNALFD
	args->sig_fd = signalfd(args->sig_fd, &args->sig_mask, SFD_CLOEXEC);
	if (args->sig_fd == -1)
		return -1;
#endif

	if (args->in != -1) {
		(void)fcntl(args->in, F_SETFD, FD_CLOEXEC);
	}

	if (args->out != -1) {
		(void)fcntl(args->out, F_SETFD, FD_CLOEXEC);
	}

	return 0;
}

static
int fdobex_ctrans_disconnect(obex_t __unused *handle, void *customdata)
{
	struct fdobex_args *args = customdata;

	args->in = -1;
	args->out = -1;

	return 0;
}

static 
int fdobex_ctrans_read(obex_t __unused *handle, void *customdata, void *buf, int max)
{
	struct fdobex_args *args = customdata;

	return (int)read(args->in, buf, max);
}

static
int fdobex_ctrans_write(obex_t __unused *handle, void *customdata, uint8_t *buf, int buflen)
{
	struct fdobex_args *args = customdata;

	return write(args->out, buf, buflen);
}

static
int fdobex_ctrans_handleinput(obex_t *handle, void *customdata, int timeout)
{
	struct fdobex_args *args = customdata;
	struct timeval time = {
		.tv_sec = timeout,
		.tv_usec = 0,
	};
	struct timeval *timep = &time;
	fd_set fdset;
	int ret;
	int maxfd = 0;

	if (args->in == -1 || args->sig_fd == -1)
		return -1;

	FD_ZERO(&fdset);
	FD_SET(args->in, &fdset);
	if (args->in > maxfd)
		maxfd = args->in;
#if HAS_SIGNALFD
	FD_SET(args->sig_fd, &fdset);
	if (args->sig_fd > maxfd)
		maxfd = args->sig_fd;
#endif

	if (timeout < 0)
		timep = NULL;
	ret = select(maxfd+1, &fdset, NULL, NULL, timep);
	if (ret > 0) {
		if (FD_ISSET(args->in, &fdset)) {
			int n = fdobex_ctrans_read(handle, customdata, args->buf, OBEX_MAXIMUM_MTU);
			if (n > 0)
				ret = OBEX_CustomDataFeed(handle, args->buf, n);
			else {
				/* This can happens when the client disappears early */
				OBEX_TransportDisconnect(handle);
				ret = -1;
			}
#if HAS_SIGNALFD
		} else if (FD_ISSET(args->sig_fd, &fdset)) {
			struct signalfd_siginfo info;
			memset(&info, 0, sizeof(info));
			(void)read(args->sig_fd, &info, sizeof(info));
			if (info.ssi_signo == SIGHUP) {
				OBEX_TransportDisconnect(handle);
				ret = -1;
			}
#endif
		}
	}

	return ret;
}

void fdobex_ctrans_set (obex_ctrans_t *ctrans)
{
	ctrans->disconnect = fdobex_ctrans_disconnect;
	ctrans->listen = fdobex_ctrans_listen;
	ctrans->write = fdobex_ctrans_write;
	ctrans->handleinput = fdobex_ctrans_handleinput;
}
