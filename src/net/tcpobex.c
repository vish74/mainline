
#define _GNU_SOURCE

#include "net.h"
#include "compiler.h"
#include "publish/avahi.h"

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

#ifdef ENABLE_TCPWRAP
#include <tcpd.h>
int allow_severity;
int deny_severity;
#endif

struct tcp_args {
	char* address;
	uint16_t port;
	char* intf;
#ifdef ENABLE_AVAHI
	void *avahi;
#endif
};

static
obex_t* tcp_init (
	struct net_handler *h,
	obex_event_t eventcb
)
{
	struct tcp_args* args = h->args;
	obex_t* handle = OBEX_Init(OBEX_TRANS_INET,eventcb,OBEX_FL_KEEPSERVER);
	
	if (!handle)
		return NULL;

	{
		union {
			struct sockaddr     raw;
			struct sockaddr_in  in4;
			struct sockaddr_in6 in6;
		} addr;
		char* addrstr = args->address;
		int af = AF_UNSPEC;

		if (!args->address || strcmp(args->address, "*") == 0)
			addrstr = "::";
			
		if (!args->intf) {
			char* intf = strchr(addrstr, '%');
			if (intf) {
				*intf = 0;
				args->intf = strdup(intf+1);
			}
		}
		if (inet_pton(AF_INET6, addrstr, &addr.in6.sin6_addr) == 1) {
			addr.raw.sa_family = AF_INET6;
			addr.in6.sin6_port = htons(args->port);
			addr.in6.sin6_flowinfo = 0;
			addr.in6.sin6_scope_id = 0;
			if (IN6_IS_ADDR_LINKLOCAL(&addr.in6.sin6_addr)) {
				if (args->intf)
					addr.in6.sin6_scope_id = if_nametoindex(args->intf);
			}

		} else if (inet_pton(AF_INET, args->address, &addr.in4.sin_addr) == 1) {
			addr.raw.sa_family = af = AF_INET;
			addr.in4.sin_port = htons(args->port);

		} else {
			return NULL;
		}

		if (TcpOBEX_ServerRegister(handle, &addr.raw, sizeof(addr)) == -1) {
			perror("TcpOBEX_ServerRegister");
			return NULL;

		} else {
			fprintf(stderr, "Listening on tcp/%s:%d\n",
				(args->address? args->address: "*"),
				args->port);
		}

#ifdef ENABLE_AVAHI
		args->avahi = obex_avahi_setup(af, args->port, args->intf);
#endif
		
	}
	return handle;
}

#ifdef ENABLE_AVAHI
static
void tcp_cleanup (
	struct net_handler *h
)
{
	struct tcp_args* args = h->args;

	if (args->avahi)
		obex_avahi_cleanup(args->avahi);
}
#define TCP_CLEANUP_FUNC tcp_cleanup
#else
#define TCP_CLEANUP_FUNC NULL
#endif

static
int tcp_security_check(
	struct net_handler __unused *h,
	obex_t *ptr
)
{
#ifdef ENABLE_TCPWRAP
	int err = 1;
	int sock = OBEX_GetFD(ptr);
	struct sockaddr_in6 client, server;
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
int tcp_get_peer(
	obex_t* handle,
	char* buffer,
	size_t bufsiz
)
{
	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(addr);
	char addrstr[INET6_ADDRSTRLEN];
	char tmp[256];

	int status;
	int sock = OBEX_GetFD(handle);

	if (sock == -1)
		return -EBADF;
	status = getpeername(sock, (struct sockaddr*) &addr, &addrlen);
	if (status == -1)
		return -errno;

	if (addr.sin6_family != AF_INET6)
		return -EBADF;

	memset(addrstr, 0, sizeof(addrstr));
	if (inet_ntop(AF_INET6, &addr.sin6_addr, addrstr, sizeof(addrstr)) == NULL)
		return -errno;
	status = snprintf(tmp, sizeof(tmp), "tcp/[%s]:%u", addrstr, addr.sin6_port);

	if (buffer)
		strncpy(buffer, tmp, bufsiz);

	return status;
}

static
struct net_handler_ops tcp_ops = {
	.init = tcp_init,
	.cleanup = TCP_CLEANUP_FUNC,
	.get_peer = tcp_get_peer,
	.security_check = tcp_security_check,
};

struct net_handler* tcp_setup(
	const char* address,
	uint16_t port
)
{
	struct tcp_args* args;
	struct net_handler *h = net_handler_alloc(&tcp_ops, sizeof(*args));

	if (!h)
		return NULL;

	args = h->args;

	if (address) {
		args->address = strdup(address);
		if (!args->address) {
			int err = errno;
			net_handler_cleanup(h);
			errno = err;
			return NULL;
		}
	} else
		args->address = NULL;
	args->port = port;
	args->intf = NULL;

	return 0;
}
