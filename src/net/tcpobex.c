#include "net.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

struct tcp_args {
	char* address;
	uint16_t port;
	char* intf;
};

static
obex_t* _tcp_init (
	struct tcp_args* args,
	obex_event_t eventcb
)
{
	obex_t* handle = OBEX_Init(OBEX_TRANS_INET,eventcb,OBEX_FL_KEEPSERVER);
	
	if (!handle)
		return NULL;

	{
		union {
			struct sockaddr     raw;
			struct sockaddr_in  in4;
			struct sockaddr_in6 in6;
		} addr;

		if (inet_pton(AF_INET6,args->address,&addr.in6.sin6_addr) == 1) {
			addr.raw.sa_family = AF_INET6;
			addr.in6.sin6_port = htons(args->port);
			addr.in6.sin6_flowinfo = 0;
			addr.in6.sin6_scope_id = 0;
			if (IN6_IS_ADDR_LINKLOCAL(&addr.in6.sin6_addr) && args->intf) {
				addr.in6.sin6_scope_id = if_nametoindex(args->intf);
			}
		} else if (inet_pton(AF_INET,args->address,&addr.in4.sin_addr) == 1) {
			addr.raw.sa_family = AF_INET;
			addr.in4.sin_port = htons(args->port);
		} else {
			return NULL;
		}

		if (TcpOBEX_ServerRegister(handle,&addr.raw,sizeof(addr)) == -1) {
			perror("TcpOBEX_ServerRegister");
			return NULL;
		} else {
			fprintf(stderr,"Listening on TCP/%s:%d",args->address,args->port);
		}
	}
	return handle;
}

static
obex_t* tcp_init(
	void* arg,
	obex_event_t eventcb
)
{
	return _tcp_init((struct tcp_args*)arg, eventcb);
}

static
struct net_funcs tcp_funcs = {
	.init = tcp_init
};

int tcp_setup(
	struct net_data* data,
	const char* address,
	uint16_t port,
	const char* intf
)
{
	struct tcp_args* args = malloc(sizeof(*args));
	data->arg = args;
	if (!args)
		return -errno;

	if (address)
		args->address = strdup(address);
	else
		args->address = NULL;
	args->port = port;
	if (args->intf)
		args->intf = strdup(intf);
	else
		args->intf = NULL;
	data->funcs = &tcp_funcs;
	return 0;
}