
/* Information about the USB OBEX gadget device (Linux):
 * - SIGHUP is raised when the client is disconnected (e.g. cable removed)
 * - since USB CDC uses block transfers, a read must always offer a maximum size
 *   buffer of 0xFFFF, the actual read data may be less
 * - the TTY device must be set into raw mode
 * - when the client is closing the connection, read() after select() will
 *   return 0 bytes, the device file must be re-opened in this case
 * - expect freezes when using dummy_hcd.ko (something is wrong with it, 2.6.33)
 */

#include "closexec.h"
#include "net.h"
#include "compiler.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#ifndef HAS_SIGNALFD
#define HAS_SIGNALFD 1
#endif
#if HAS_SIGNALFD
#  include <sys/signalfd.h>
#  include <sys/signal.h>
#endif

struct usb_gadget_args {
	char* device;
	int fd;
	obex_ctrans_t ctrans;
#if HAS_SIGNALFD
	sigset_t sig_mask;
	int sig_fd;
#endif
	uint8_t *buf;
};

static
int usb_gadget_ctrans_listen(obex_t __unused *handle, void * customdata)
{
	int ret = -1;
	struct usb_gadget_args *args = customdata;

#if HAS_SIGNALFD
	args->sig_fd = signalfd(args->sig_fd, &args->sig_mask, SFD_CLOEXEC);
	if (args->sig_fd == -1)
		return ret;
#endif

	if (args->fd == -1) {
		args->fd = open_closexec(args->device, O_RDWR | O_NOCTTY, 0);
		if (args->fd != -1) {
			struct termios t;

			ret = tcgetattr(args->fd, &t);
			if (ret != -1) {
				cfmakeraw(&t);
				(void)tcsetattr(args->fd, 0, &t);
				(void)tcflush(args->fd, TCIOFLUSH);
				ret = 0;
			}
		}
	}

	return ret;
}

static
int usb_gadget_ctrans_disconnect(obex_t *handle, void * customdata)
{
	struct usb_gadget_args *args = customdata;

	/* re-initialize the file descriptors, else the select() will
	 * always return after a very short time but read() returns 0.
	 * tcflush() doesn't work.
	 */
	if (args->fd != -1) {
		close(args->fd);
		args->fd = -1;
	}
#if HAS_SIGNALFD
	if (args->sig_fd != -1) {
		close(args->sig_fd);
		args->sig_fd = -1;
	}
#endif
	(void)usb_gadget_ctrans_listen(handle, customdata);

	return 0;
}

static 
int usb_gadget_ctrans_read(obex_t __unused *handle, void *customdata, void *buf, int max)
{
	struct usb_gadget_args *args = customdata;

	if (max < OBEX_MAXIMUM_MTU)
		return -1;

	return (int)read(args->fd, buf, OBEX_MAXIMUM_MTU);
}

static
int usb_gadget_ctrans_write(obex_t __unused *handle, void *customdata, uint8_t *buf, int buflen)
{
	struct usb_gadget_args *args = customdata;

	return write(args->fd, buf, buflen);
}

static
int usb_gadget_ctrans_handleinput(obex_t *handle, void *customdata, int timeout)
{
	struct usb_gadget_args *args = customdata;
	struct timeval time = {
		.tv_sec = timeout,
		.tv_usec = 0,
	};
	struct timeval *timep = &time;
	fd_set fdset;
	int ret;
	int maxfd = 0;

	FD_ZERO(&fdset);
	FD_SET(args->fd, &fdset);
	if (args->fd > maxfd)
		maxfd = args->fd;
#if HAS_SIGNALFD
	FD_SET(args->sig_fd, &fdset);
	if (args->sig_fd > maxfd)
		maxfd = args->sig_fd;
#endif

	if (timeout < 0)
		timep = NULL;
	ret = select(maxfd+1, &fdset, NULL, NULL, timep);
	if (ret > 0) {
		if (FD_ISSET(args->fd, &fdset)) {
			int n = usb_gadget_ctrans_read(handle, customdata, args->buf, OBEX_MAXIMUM_MTU);
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
obex_t* usb_gadget_init (
	struct net_handler *h,
	obex_event_t eventcb
)
{
	struct usb_gadget_args *args = h->args;
	obex_t *handle = NULL;

	args->buf = malloc(OBEX_MAXIMUM_MTU);
	if (args->buf)
		handle = OBEX_Init(OBEX_TRANS_CUSTOM, eventcb, 0);

	if (handle) {
		int ret = OBEX_RegisterCTransport(handle, &args->ctrans);
		if (ret == -1) {
			perror("OBEX_RegisterCTransport");
			OBEX_Cleanup(handle);
			handle = NULL;

		} else {
			if (OBEX_ServerRegister(handle, NULL, 0) < 0) {
				OBEX_Cleanup(handle);
				handle = NULL;
				fprintf(stderr, "Error: cannot open %s: %s\n", args->device, strerror(errno));
			} else {
				OBEX_SetTransportMTU(handle, OBEX_MAXIMUM_MTU, OBEX_MAXIMUM_MTU);
				fprintf(stderr, "Listening on file/%s\n", args->device);
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
void usb_gadget_cleanup (
	struct net_handler *h
)
{
	struct usb_gadget_args *args = h->args;

	if (args->fd != -1) {
		close(args->fd);
		args->fd = -1;
	}
#if HAS_SIGNALFD
	if (args->sig_fd != -1) {
		close(args->sig_fd);
		args->sig_fd = -1;
	}
#endif
	if (args->device) {
		free(args->device);
		args->device = NULL;
	}
	if (args->buf) {
		free(args->buf);
		args->buf = NULL;
	}
}

static
int usb_gadget_get_peer(
	struct net_handler __unused *h,
	obex_t __unused *handle,
	char* buffer,
	size_t bufsiz
)
{	
	struct usb_gadget_args *args = h->args;

	return snprintf(buffer, bufsiz, "file/%s", args->device);
}

static
int usb_gadget_get_listen_fd (
	struct net_handler *h
)
{
	struct usb_gadget_args *args = h->args;

	return args->fd;
}

static
struct net_handler_ops usb_gadget_ops = {
	.init = usb_gadget_init,
	.cleanup = usb_gadget_cleanup,
	.get_peer = usb_gadget_get_peer,
	.get_listen_fd = usb_gadget_get_listen_fd,
};

struct net_handler* usb_gadget_setup(
	const char* device,
	time_t __unused timeout
)
{
	struct usb_gadget_args* args;
	struct net_handler *h = net_handler_alloc(&usb_gadget_ops, sizeof(*args));
	obex_ctrans_t *ctrans;

	if (!h)
		return NULL;

	args = h->args;
	ctrans = &args->ctrans;

	ctrans->disconnect = usb_gadget_ctrans_disconnect;
	ctrans->listen = usb_gadget_ctrans_listen;
	ctrans->write = usb_gadget_ctrans_write;
	ctrans->handleinput = usb_gadget_ctrans_handleinput;
	ctrans->customdata = args;

	args->device = strdup(device);
	args->fd = -1;

#if HAS_SIGNALFD
	(void)sigemptyset(&args->sig_mask);
	args->sig_fd = -1;
#endif

	return h;
}
