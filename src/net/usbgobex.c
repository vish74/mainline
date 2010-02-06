
#include "closexec.h"
#include "net.h"
#include "compiler.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/signal.h>
#include <termios.h>
#include <unistd.h>

struct usb_gadget_args {
	char* device;
	int fd;
	obex_ctrans_t ctrans;

	sigset_t sig_mask;
	int sig_fd;

	uint8_t buf[1024];
};

static
int usb_gadget_listen(obex_t *handle, void * customdata)
{
	struct usb_gadget_args *args = customdata;

	args->sig_fd = signalfd(args->sig_fd, &args->sig_mask, SFD_CLOEXEC);
	if (args->fd == -1) {
		struct termios t;

		args->fd = open_closexec(args->device, O_RDWR | O_NOCTTY, 0);
		if (args->fd == -1) {
			fprintf(stderr, "Error: cannot open %s: %s\n", args->device, strerror(errno));
			return -1;
		}
		if (tcgetattr(args->fd, &t) != -1) {
			cfmakeraw(&t);
			(void)tcsetattr(args->fd, 0, &t);
			(void)tcflush(args->fd, TCIOFLUSH);
		}
	}
	return 0;
}

static
int usb_gadget_write(obex_t *handle, void * customdata, uint8_t *buf, int buflen)
{
	struct usb_gadget_args *args = customdata;

	return write(args->fd, buf, buflen);
}

static
int usb_gadget_handleinput(obex_t *handle, void * customdata, int timeout)
{
	struct usb_gadget_args *args = customdata;
	struct timeval time = {
		.tv_sec = timeout,
		.tv_usec = 0,
	};
	struct timeval *timep = &time;
	fd_set fdset;
	int ret;

	FD_ZERO(&fdset);
	FD_SET(args->fd, &fdset);
	FD_SET(args->sig_fd, &fdset);

	if (timeout < 0)
		timep = NULL;
	ret = select((int)args->fd+1, &fdset, NULL, NULL, timep);
	if (ret > 0) {
		if (FD_ISSET(args->fd, &fdset)) {
			ssize_t n = read(args->fd, args->buf, sizeof(args->buf));
			ret = OBEX_CustomDataFeed(handle, args->buf, n);

		} else if (FD_ISSET(args->sig_fd, &fdset)) {
			struct signalfd_siginfo info;
			memset(&info, 0, sizeof(info));
			(void)read(args->sig_fd, &info, sizeof(info));
			if (info.ssi_signo == SIGHUP)
				ret = -1;
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
	obex_t *handle = OBEX_Init(OBEX_TRANS_CUSTOM, eventcb, 0);

	if (!handle)
		return NULL;

	else {
		if (OBEX_RegisterCTransport(handle, &args->ctrans) == -1) {
			perror("OBEX_RegisterCTransport");
			return NULL;
		}
		(void)OBEX_ServerRegister(handle, NULL, 0);
		OBEX_SetTransportMTU(handle, sizeof(args->buf), sizeof(args->buf));
		fprintf(stderr, "Listening on file/%s\n", args->device);
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
	if (args->device) {
		free(args->device);
		args->device = NULL;
	}
}

static
int usb_gadget_get_peer(
	struct net_handler __unused *h,
	obex_t* handle,
	char* buffer,
	size_t bufsiz
)
{	
	struct usb_gadget_args *args = h->args;

	return snprintf(buffer, bufsiz, "file/%s", args->device);
}

static
void usb_gadget_disconnect (
	struct net_handler __unused *h,
	obex_t __unused *handle
)
{
}

static
struct net_handler_ops usb_gadget_ops = {
	.init = usb_gadget_init,
	.cleanup = usb_gadget_cleanup,
	.get_peer = usb_gadget_get_peer,
	.disconnect = usb_gadget_disconnect,
};

struct net_handler* usb_gadget_setup(
	const char* device,
	int timeout
)
{
	struct usb_gadget_args* args;
	struct net_handler *h = net_handler_alloc(&usb_gadget_ops, sizeof(*args));
	obex_ctrans_t *ctrans;

	if (!h)
		return NULL;

	args = h->args;
	ctrans = &args->ctrans;

	ctrans->listen = usb_gadget_listen;
	ctrans->write = usb_gadget_write;
	ctrans->handleinput = usb_gadget_handleinput;
	ctrans->customdata = args;

	args->device = strdup(device);
	args->fd = -1;
	(void)sigemptyset(&args->sig_mask);
	args->sig_fd = -1;

	return h;
}
