#define _GNU_SOURCE

#include "net.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <linux/types.h>
#include <linux/irda.h>

struct irda_args {
	char* service;
};

static
obex_t* irda_init (
	struct net_handler *h,
	obex_event_t eventcb
)
{
	struct irda_args* args = h->args;
	obex_t* handle = OBEX_Init(OBEX_TRANS_IRDA,eventcb,OBEX_FL_KEEPSERVER);
	
	if (!handle)
		return NULL;

	if (IrOBEX_ServerRegister(handle,args->service) == -1) {
		perror("IrOBEX_ServerRegister");
		return NULL;
	}
	OBEX_SetTransportMTU(handle, OBEX_IRDA_OPT_MTU, OBEX_IRDA_OPT_MTU);
	fprintf(stderr,"Listening on IrDA service \"%s\"\n", args->service);
	return handle;
}

static
int irda_get_peer(
	obex_t* handle,
	char* buffer,
	size_t bufsiz
)
{
	struct sockaddr_irda addr;
	socklen_t addrlen = sizeof(addr);
	char tmp[256];

	int status;
	int sock = OBEX_GetFD(handle);

	if (sock == -1)
		return -EBADF;
	status = getpeername(sock, (struct sockaddr*) &addr, &addrlen);
	if (status == -1)
		return -errno;
	if (addr.sir_family != AF_IRDA)
		return -EBADF;

	status = snprintf(tmp, sizeof(tmp), "irda/[%8X]%s%s", addr.sir_addr,
			  (strlen(addr.sir_name)? ":": ""), addr.sir_name);

	if (buffer)
		strncpy(buffer, tmp, bufsiz);

	return status;
}

static
struct net_handler_ops irda_ops = {
	.init = irda_init,
	.get_peer = irda_get_peer
};

struct net_handler* irda_setup(
	char* service
)
{
	struct irda_args* args;
	struct net_handler *h = net_handler_alloc(&irda_ops, sizeof(*args));

	if (!h)
		return NULL;

	args = h->args;

	if (service) {
		size_t slen = 5 + strlen(service) + 1;
		char* s = malloc(slen);
		if (!s) {
			int err = errno;
			net_handler_cleanup(h);
			errno = err;
			return NULL;
		}
		(void)snprintf(s,slen,"OBEX:%s",service);
		args->service = s;
	} else {
		args->service = strdup("OBEX");
	}

	return 0;
}
