#include "net.h"

#include <arpa/inet.h>
#include <errno.h>

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
int inet_get_peer(
	obex_t* handle,
	char* buffer,
	size_t bufsiz
)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	char addrstr[INET6_ADDRSTRLEN];
	uint16_t port;
	char tmp[256];

	int status;
	int sock = OBEX_GetFD(handle);

	if (sock == -1)
		return -EBADF;
	status = getpeername(sock, (struct sockaddr*) &addr, &addrlen);
	if (status == -1)
		return -errno;

	memset(addrstr, 0, sizeof(addrstr));
	switch (((struct sockaddr_in*)&addr)->sin_family) {
	case AF_INET:
		if (inet_ntop(AF_INET, &((struct sockaddr_in*)&addr)->sin_addr, addrstr, sizeof(addrstr)) == NULL)
			return -errno;
		port = ((struct sockaddr_in*)&addr)->sin_port;
		break;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &((struct sockaddr_in6*)&addr)->sin6_addr, addrstr, sizeof(addrstr)) == NULL)
			return -errno;
		port = ((struct sockaddr_in6*)&addr)->sin6_port;
		break;

	default:
		return -EBADF;
	}
	status = snprintf(tmp, sizeof(tmp), "tcp/[%s]:%u", addrstr, port);

	if (buffer)
		strncpy(buffer, tmp, bufsiz);

	return status;
}

static
struct net_funcs inet_funcs = {
	.init = inet_init,
	.get_peer = inet_get_peer
};

int inet_setup(struct net_data* data) {
	data->funcs = &inet_funcs;
	return 0;
}
