/* Information about the USB OBEX gadget device (Linux):
 * - SIGHUP is raised when the client is disconnected (e.g. cable removed)
 * - since USB CDC uses block transfers, a read must always offer a maximum size
 *   buffer of 0xFFFF, the actual read data may be less
 * - the TTY device must be set into raw mode
 * - when the client is closing the connection, read() after select() will
 *   return 0 bytes, the device file must be re-opened in this case
 * - expect freezes when using dummy_hcd.ko (something is wrong with it, 2.6.33)
 */

#include "compiler.h"
#include "usbgobex.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

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
				fprintf(stderr,
					"Error: cannot open %s: %s\n",
					args->device, strerror(errno));
			} else {
				OBEX_SetTransportMTU(handle,
						     OBEX_MAXIMUM_MTU,
						     OBEX_MAXIMUM_MTU);
				fprintf(stderr,
					"Listening on file/%s\n",
					args->device);
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
	time_t timeout
)
{
	struct usb_gadget_args* args;
	struct net_handler *h = net_handler_alloc(&usb_gadget_ops,
						  sizeof(*args));

	if (!h)
		return NULL;

	args = h->args;
	args->device = strdup(device);
	args->timeout = timeout;
	args->fd = -1;
	usbgobex_ctrans_set(&args->ctrans);
	args->ctrans.customdata = args;

#if HAS_SIGNALFD
	(void)sigemptyset(&args->sig_mask);
	args->sig_fd = -1;
#endif

	return h;
}
