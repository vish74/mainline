
/* Information typical usage of standard I/O descriptors:
 * - SIGHUP is raised when the client is disconnected
 */

#include "fdobex.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
/* #include <fcntl.h> */

#include "compiler.h"

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

	if (!h)
		return NULL;

	args = h->args;
	args->in = in;
	args->out = out;
	fdobex_ctrans_set(&args->ctrans);
	args->ctrans.customdata = args;

#if HAS_SIGNALFD
	(void)sigemptyset(&args->sig_mask);
	args->sig_fd = -1;
#endif

	return h;
}
