#include "net.h"
#include "compiler.h"
#include "publish/sdp.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci_lib.h>
#include <sys/socket.h>

struct bluetooth_args {
	void* session_data;
	bdaddr_t device;
	uint8_t channel;
	unsigned long protocols;
};

static
obex_t* bluetooth_init (
	struct net_handler *h,
	obex_event_t eventcb
)
{
	struct bluetooth_args* args = h->args;
	obex_t* handle = OBEX_Init(OBEX_TRANS_BLUETOOTH,eventcb,OBEX_FL_KEEPSERVER);
	char device[18];
  
	if (!handle)
		return NULL;

	if (args->channel) {
		/* the user selected a specific channel */
		if (BtOBEX_ServerRegister(handle, &args->device, args->channel) == -1) {
			perror("BtOBEX_ServerRegister");
			return NULL;
		}
	} else {
		/* automatically find a free channel:
		 * Our previous default was channel 9, so try it first.
		 */
		unsigned int i = 9;
		if (BtOBEX_ServerRegister(handle, &args->device, i) != -1) {
			for (i = 1; i < UINT8_MAX; ++i) {
				if (i != 9 && BtOBEX_ServerRegister(handle, &args->device, i) != -1)
					break;
			}
		}
		if (i >= UINT8_MAX) {
			fprintf(stderr, "Cannot find a free RFCOMM channel\n");
			return NULL;
		}
		args->channel = (uint8_t)i;
	}
	OBEX_SetTransportMTU(handle, OBEX_MAXIMUM_MTU, OBEX_MAXIMUM_MTU);
	(void)ba2str(&args->device, device);
	fprintf(stderr, "Listening on bluetooth/[%s]:%u\n", device, (unsigned int)args->channel);

	args->session_data = bt_sdp_session_open(&args->device, args->channel, args->protocols);
	if (!args->session_data) {
		fprintf(stderr, "SDP session setup failed, disabling bluetooth\n");
		OBEX_Cleanup(handle);
		return NULL;
	}
	return handle;
}

static
void bluetooth_cleanup(
	struct net_handler *h
)
{
	struct bluetooth_args* args = h->args;

	if (args->session_data) {
		bt_sdp_session_close(args->session_data, &args->device);
		args->session_data = NULL;
	}
}

static
int bluetooth_security_init(
	struct net_handler __unused *h,
	obex_t *ptr
)
{
	int sock = OBEX_GetFD(ptr);
	int err = 0;
	const uint32_t options = (RFCOMM_LM_AUTH | RFCOMM_LM_SECURE);
	uint32_t optval = 0;
	socklen_t optlen = sizeof(optval);

	if (sock < 0)
		return -ENOTSOCK;

	err = getsockopt(sock, SOL_RFCOMM, RFCOMM_LM, &optval, &optlen);
	if (err < 0) {
		perror("Getting RFCOMM_LM");
		return -errno;
	}
	if (optlen != sizeof(optval))
		return -EINVAL;

	if ((optval & options) != options) {
		optval |= options;
		err = setsockopt(sock, SOL_RFCOMM, RFCOMM_LM, &optval, optlen);
		if (err < 0) {
			perror("Setting RFCOMM_LM");
			return -errno;
		}
	}
	return 0;
}

static
int bluetooth_get_peer(
	struct net_handler __unused *h,
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
void bluetooth_set_protocol (
	struct net_handler *h,
	enum net_obex_protocol prot
)
{
	struct bluetooth_args* args = h->args;

	switch (prot) {
	case NET_OBEX_PUSH:
		args->protocols |= BT_SDP_PROT_OBEX_PUSH;
		break;

	case NET_OBEX_FTP:
		args->protocols |= BT_SDP_PROT_OBEX_FTP;
		break;
	}
}

static
struct net_handler_ops bluetooth_ops = {
	.init = bluetooth_init,
	.cleanup = bluetooth_cleanup,
	.set_protocol = bluetooth_set_protocol,
	.get_peer = bluetooth_get_peer,
	.security_init = bluetooth_security_init
};

struct net_handler* bluetooth_setup(
	char* device,
	uint8_t channel
)
{
	struct bluetooth_args* args;
	struct net_handler *h = net_handler_alloc(&bluetooth_ops, sizeof(*args));
	int hciId  = -1;

	if (!h)
		return NULL;

	args = h->args;

	if (device) {
		int id;
		if (strlen(device) == 17) /* 11:22:33:44:55:66 */
			id = hci_devid(device);
		else if (1 != sscanf(device, "hci%d", &id))
			id = -1;
		hciId = id;
	}

	if (hciId >= 0)
		hci_devba(hciId, &args->device);
	else
		bacpy(&args->device, BDADDR_ANY);
	args->channel = channel;

	return h;
}
