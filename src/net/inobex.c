#include "net.h"

#include <arpa/inet.h>
#include <errno.h>

#ifdef ENABLE_TCPWRAP
#include <tcpd.h>
int allow_severity;
int deny_severity;
#endif

static
obex_t* inet_init (
	struct net_handler __unused *h,
	obex_event_t eventcb
)
{
	obex_t* handle = OBEX_Init(OBEX_TRANS_INET,eventcb,OBEX_FL_KEEPSERVER);
	
	if (!handle)
		return NULL;

	{
		if (InOBEX_ServerRegister(handle) == -1) {
			perror("InOBEX_ServerRegister");
			return NULL;
		}
		OBEX_SetTransportMTU(handle, OBEX_MAXIMUM_MTU, OBEX_MAXIMUM_MTU);
		fprintf(stderr,"Listening on tcp/*:650\n");
	}

	return handle;
}

static
int inet_security_check(
	struct net_handler *h,
	obex_t* ptr
)
{
#ifdef ENABLE_TCPWRAP
	int err = 1;
	int sock = OBEX_GetFD(ptr);
	struct sockaddr_in client, server;
	socklen_t len;
	struct request_info req;

	len = sizeof(client);
	err = getpeername(sock, (struct sockaddr*)&client, &len);
	if (err < 0)
		return 0;

	len = sizeof(server);
	err = getsockname(sock, (struct sockaddr*)&server, &len);
	if (err < 0)
		return 0;

	request_init(&req,
		     RQ_FILE, sock,
		     RQ_CLIENT_SIN, client,
		     RQ_SERVER_SIN, server,
		     RQ_DAEMON, "obexpushd");
	fromhost(&req);

	return  hosts_access(&req);

#else
	return 1;
#endif
}

static
int inet_get_peer(
	struct net_handler __unused *h,
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
struct net_handler_ops inet_ops = {
	.init = inet_init,
	.get_peer = inet_get_peer,
	.security_check = inet_security_check,
};

struct net_handler* inet_setup() {
	return net_handler_alloc(&inet_ops, 0);
}
