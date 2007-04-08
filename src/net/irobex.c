#define _GNU_SOURCE

#include "net.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

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
struct net_funcs irda_funcs = {
	.init = irda_init
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
