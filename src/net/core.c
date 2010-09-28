#include "net.h"
#include "auth.h"
#include <obex_auth.h>

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

struct net_handler* net_handler_alloc(struct net_handler_ops *ops, size_t argsize)
{
	struct net_handler *h = malloc(sizeof(*h));

	if (!h)
		return NULL;

	if (argsize) {
		h->args = malloc(argsize);
		if (!h->args) {
			int err = errno;
			free(h);
			errno = err;
			return NULL;
		}
		memset(h->args, 0, argsize);
	} else
		h->args = NULL;

	h->ops = ops;

	return h;
}

void net_handler_cleanup(struct net_handler *h)
{
  	if (h->args) {
		if (h->ops && h->ops->cleanup)
			h->ops->cleanup(h);
		free(h->args);
		h->args = NULL;
	}
	h->ops = NULL;
}

struct net_data* net_data_new ()
{
	struct net_data* data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	data->obex = NULL;
	data->handler = NULL;

	data->auth_success = 0;
	return data;
}

void net_init (
	struct net_data* data,
	obex_event_t eventcb
)
{
	struct net_handler *h = data->handler;

	/* enable protocols */
	if (h && h->ops->set_protocol) {
		if ((data->enabled_protocols & (1 << NET_OBEX_PUSH)) != 0)
			h->ops->set_protocol(h, NET_OBEX_PUSH);
		if ((data->enabled_protocols & (1 << NET_OBEX_FTP)) != 0)
			h->ops->set_protocol(h, NET_OBEX_FTP);
	}

	if (h && h->ops->init) {
		if (data->obex)
			OBEX_Cleanup(data->obex);
		data->obex = h->ops->init(h, eventcb);
	}
	if (data->obex) {
		int fd = OBEX_GetFD(data->obex);
		if (fd >= 0)
			(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
		OBEX_SetUserData(data->obex, data);
	}

	if ((data->auth_level & AUTH_LEVEL_TRANSPORT) &&
	    h && h->ops->security_init)
	{
		h->ops->security_init(h, data->obex);
	}
}

void net_disconnect (
	struct net_data* data
)
{
	(void)OBEX_TransportDisconnect(data->obex);
}

uint8_t net_security_init (
	struct net_data* data,
	struct auth_handler* auth,
	obex_object_t* obj
)
{
	struct net_handler *h = data->handler;

	if ((data->auth_level & AUTH_LEVEL_TRANSPORT) &&
	    h && h->ops->security_check &&
	    !h->ops->security_check(h, data->obex))
	{
		return OBEX_RSP_FORBIDDEN;
	}

	if ((data->auth_level & AUTH_LEVEL_OBEX) &&
	    !data->auth_success)
	{
		if (auth && auth_init(auth, data->obex, obj))
			return OBEX_RSP_UNAUTHORIZED;
		else
			return OBEX_RSP_SERVICE_UNAVAILABLE;
	}

	return 0;
}

int net_security_check (struct net_data* data)
{
	int transport = 1;
	int obex = 1;
	struct net_handler *h = data->handler;

	if ((data->auth_level & AUTH_LEVEL_TRANSPORT) &&
	    h && h->ops->security_check)
		transport = h->ops->security_check(h, data->obex);

	if ((data->auth_level & AUTH_LEVEL_OBEX))
		obex = data->auth_success;

	return transport && obex;
}

void net_get_peer (struct net_data* data, char* buffer, size_t bufsiz)
{
	struct net_handler *h = data->handler;

	if (h && h->ops->get_peer)
		(void)h->ops->get_peer(h, data->obex, buffer, bufsiz);
}

int net_get_listen_fd(struct net_data* data)
{
	struct net_handler *h = data->handler;

	if (h && h->ops->get_listen_fd)
		return h->ops->get_listen_fd(h);
	else
		return OBEX_GetFD(data->obex);
	
}

void net_cleanup (struct net_data* data)
{
	if (data->handler) {
		net_handler_cleanup(data->handler);
		data->handler = NULL;
	}
	if (data->obex) {
		OBEX_Cleanup(data->obex);
		data->obex = NULL;
	}
}
