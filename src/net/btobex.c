#include "net.h"
#include "obexpush-sdp.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <sys/socket.h>

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
int bluetooth_get_peer(
	obex_t* handle,
	char* buffer,
	size_t bufsiz
)
{
	struct sockaddr_rc addr;
	socklen_t addrlen = sizeof(addr);
	char addrstr[128];
	char tmp[256];

	int status;
	int sock = OBEX_GetFD(handle);

	if (sock == -1)
		return -EBADF;
	status = getpeername(sock, (struct sockaddr*) &addr, &addrlen);
	if (status == -1)
		return -errno;
	if (addr.rc_family != AF_BLUETOOTH)
		return -EBADF;

	memset(addrstr, 0, sizeof(addrstr));
	ba2str(&addr.rc_bdaddr, addrstr);
	status = snprintf(tmp, sizeof(tmp), "bluetooth/[%s]:%u", addrstr, addr.rc_channel);

	if (buffer)
		strncpy(buffer, tmp, bufsiz);

	return status;
}

static
struct net_funcs bluetooth_funcs = {
	.init = bluetooth_init,
	.get_peer = bluetooth_get_peer
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
