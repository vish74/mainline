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

/*@null@*/
static
obex_t* _irda_init (
	struct irda_args* args,
	obex_event_t eventcb
)
{
	obex_t* handle = OBEX_Init(OBEX_TRANS_IRDA,eventcb,OBEX_FL_KEEPSERVER);
	
	if (!handle)
		return NULL;

	if (IrOBEX_ServerRegister(handle,args->service) == -1) {
		perror("IrOBEX_ServerRegister");
		return NULL;
	}
	fprintf(stderr,"Listening on IrDA service \"%s\"\n", args->service);
	return handle;
}

static
obex_t* irda_init(
	void* arg,
	obex_event_t eventcb
)
{
	return _irda_init((struct irda_args*)arg, eventcb);
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
struct net_funcs irda_funcs = {
	.init = irda_init,
	.get_peer = irda_get_peer
};

int irda_setup(
	struct net_data* data,
	char* service
)
{
	struct irda_args* args = malloc(sizeof(*args));
	data->arg = args;
	if (!args)
		return -errno;
	
	if (service) {
		size_t slen = 5 + strlen(service) + 1;
		char* s = malloc(slen);
		if (!s)
			return -errno;
		(void)snprintf(s,slen,"OBEX:%s",service);
		args->service = s;
	} else {
		args->service = strdup("OBEX");
	}
	data->funcs = &irda_funcs;
	return 0;
}
