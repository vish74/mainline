#include "net.h"
#include "obexpush-sdp.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

struct bluetooth_args {
	uint8_t channel;
};

/*@null@*/
static
obex_t* _bluetooth_init (
	struct bluetooth_args* args,
	obex_event_t eventcb
)
{
	obex_t* handle = OBEX_Init(OBEX_TRANS_BLUETOOTH,eventcb,OBEX_FL_KEEPSERVER);
	sdp_session_t* session;
  
	if (!handle)
		return NULL;

	if (BtOBEX_ServerRegister(handle,BDADDR_ANY,args->channel) == -1) {
		perror("BtOBEX_ServerRegister");
		return NULL;
	}
	fprintf(stderr,"Listening on bluetooth channel %u\n",(unsigned int)args->channel);

	session = bt_sdp_session_open(args->channel);
	if (!session) {
		fprintf(stderr,"SDP session setup failed, disabling bluetooth\n");
		OBEX_Cleanup(handle);
		return NULL;
	}

	return handle;
}

static
obex_t* bluetooth_init(
	void* arg,
	obex_event_t eventcb
)
{
	return _bluetooth_init((struct bluetooth_args*)arg, eventcb);
}

static
struct net_funcs bluetooth_funcs = {
	.init = bluetooth_init
};

int bluetooth_setup(
	struct net_data* data,
	uint8_t channel
)
{
	struct bluetooth_args* args = malloc(sizeof(*args));
	data->arg = args;
	if (!args)
		return -errno;

	args->channel = channel;
	data->funcs = &bluetooth_funcs;
	return 0;
}
