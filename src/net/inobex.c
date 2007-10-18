#include "net.h"

static
obex_t* inet_init (
	void* arg,
	obex_event_t eventcb
)
{
	obex_t* handle = OBEX_Init(OBEX_TRANS_INET,eventcb,OBEX_FL_KEEPSERVER);
	(void)arg;
	
	if (!handle)
		return NULL;

	{
		if (InOBEX_ServerRegister(handle) == -1) {
			perror("InOBEX_ServerRegister");
			return NULL;
		} else {
			fprintf(stderr,"Listening on TCP/*:650\n");
		}
	}

	return handle;
}

static
struct net_funcs inet_funcs = {
	.init = inet_init
};

int inet_setup(struct net_data* data) {
	data->funcs = &inet_funcs;
	return 0;
}
