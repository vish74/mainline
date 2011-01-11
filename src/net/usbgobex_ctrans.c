#include "closexec.h"
#include "compiler.h"
#include "usbgobex.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static
int usbobex_ctrans_listen(obex_t __unused *handle, void * customdata)
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
int usbobex_ctrans_disconnect(obex_t *handle, void * customdata)
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

	(void)OBEX_ServerRegister(handle, NULL, 0);

	return 0;
}

static 
int usbobex_ctrans_read(obex_t __unused *handle, void *customdata,
			void *buf, int  __unused max)
{
	struct usb_gadget_args *args = customdata;

	return (int)read(args->fd, buf, OBEX_MAXIMUM_MTU);
}

static
int usbobex_ctrans_write(obex_t __unused *handle, void *customdata,
			 uint8_t *buf, int buflen)
{
	struct usb_gadget_args *args = customdata;

	return write(args->fd, buf, buflen);
}

static
int usbobex_ctrans_handleinput(obex_t *handle, void *customdata,
			       int timeout)
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
			int n = usbobex_ctrans_read(handle, customdata,
						    args->buf,
						    OBEX_MAXIMUM_MTU);
			if (n > 0)
				ret = OBEX_CustomDataFeed(handle,
							  args->buf,
							  n);
			else {
				/* This can happen when the client
				 * disappears early */
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

void usbgobex_ctrans_set (obex_ctrans_t *ctrans)
{
	ctrans->disconnect = usbobex_ctrans_disconnect;
	ctrans->listen = usbobex_ctrans_listen;
	ctrans->write = usbobex_ctrans_write;
	ctrans->handleinput = usbobex_ctrans_handleinput;
}
