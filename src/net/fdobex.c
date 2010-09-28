
/* Information typical usage of standard I/O descriptors:
 * - SIGHUP is raised when the client is disconnected
 */

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef HAS_SIGNALFD
#define HAS_SIGNALFD 1
#endif
#if HAS_SIGNALFD
#  include <sys/signalfd.h>
#  include <sys/signal.h>
#endif

#include "net.h"
#include "compiler.h"

struct fdobex_args {
	int in;
	int out;

	obex_ctrans_t ctrans;
#if HAS_SIGNALFD
	sigset_t sig_mask;
	int sig_fd;
#endif
	uint8_t *buf;
};

static
int fdobex_ctrans_listen(obex_t __unused *handle, void * customdata)
{
	struct fdobex_args *args = customdata;

#if HAS_SIGNALFD
	args->sig_fd = signalfd(args->sig_fd, &args->sig_mask, SFD_CLOEXEC);
	if (args->sig_fd == -1)
		return -1;
#endif

	if (args->in == -1) {
		(void)fcntl(args->in, F_SETFD, FD_CLOEXEC);
	}

	if (args->out == -1) {
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

static
obex_t* fdobex_init (
	struct net_handler *h,
	obex_event_t eventcb
)
{
	struct fdobex_args *args = h->args;
	obex_t *handle = NULL;

	args->buf = malloc(OBEX_MAXIMUM_MTU);
	if (args->buf)
		handle = OBEX_Init(OBEX_TRANS_CUSTOM, eventcb, 0);

	if (handle) {
		int ret = OBEX_RegisterCTransport(handle, &args->ctrans);
		if (ret == -1) {
			fprintf(stderr, "Registering OBEX custom transport failed\n");
			OBEX_Cleanup(handle);
			handle = NULL;

		} else {
			if (OBEX_ServerRegister(handle, NULL, 0) < 0) {
				OBEX_Cleanup(handle);
				handle = NULL;
				fprintf(stderr, "Error: initialising standard-I/O server failed\n");
			} else {
				OBEX_SetTransportMTU(handle, OBEX_MAXIMUM_MTU, OBEX_MAXIMUM_MTU);
				fprintf(stderr, "Listening on fd@%d:%d\n", args->in, args->out);
			}
		}
	}

	if (handle == NULL) {
		free(args->buf);
		args->buf = NULL;
	}

	return handle;
}

static
void fdobex_cleanup (
	struct net_handler *h
)
{
	struct fdobex_args *args = h->args;

#if HAS_SIGNALFD
	if (args->sig_fd != -1) {
		close(args->sig_fd);
		args->sig_fd = -1;
	}
#endif
	if (args->buf) {
		free(args->buf);
		args->buf = NULL;
	}
}

static
int fdobex_get_peer(
	struct net_handler __unused *h,
	obex_t __unused *handle,
	char* buffer,
	size_t bufsiz
)
{	
	return snprintf(buffer, bufsiz, "unknown");
}

static
int fdobex_get_listen_fd (
	struct net_handler *h
)
{
	struct fdobex_args *args = h->args;

	return args->in;
}

static
enum net_life_status fdobex_life_status (
	struct net_handler *h
)
{
	struct fdobex_args *args = h->args;

	if (args->in == -1 || args->out == -1)
		return LIFE_STATUS_DEAD;
	else
		return LIFE_STATUS_ALIVE;
}

static
struct net_handler_ops fdobex_ops = {
	.init = fdobex_init,
	.cleanup = fdobex_cleanup,
	.get_peer = fdobex_get_peer,
	.get_listen_fd = fdobex_get_listen_fd,
	.get_life_status = fdobex_life_status,
};

struct net_handler* fdobex_setup(
	int in,
	int out,
	time_t __unused timeout
)
{
	struct fdobex_args* args;
	struct net_handler *h = net_handler_alloc(&fdobex_ops, sizeof(*args));
	obex_ctrans_t *ctrans;

	if (!h)
		return NULL;

	args = h->args;
	ctrans = &args->ctrans;

	ctrans->disconnect = fdobex_ctrans_disconnect;
	ctrans->listen = fdobex_ctrans_listen;
	ctrans->write = fdobex_ctrans_write;
	ctrans->handleinput = fdobex_ctrans_handleinput;
	ctrans->customdata = args;

	args->in = in;
	args->out = out;

#if HAS_SIGNALFD
	(void)sigemptyset(&args->sig_mask);
	args->sig_fd = -1;
#endif

	return h;
}
