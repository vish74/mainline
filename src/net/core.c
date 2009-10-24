#include "net.h"
#include "auth.h"
#include <obex_auth.h>

#include <stdlib.h>
#include <fcntl.h>

struct net_data* net_data_new ()
{
	struct net_data* data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	data->arg = NULL;
	data->obex = NULL;
	data->funcs = NULL;

	data->auth_success = 0;
	return data;
}

void net_init (
	struct net_data* data,
	obex_event_t eventcb
)
{
	if (data->funcs && data->funcs->init) {
		if (data->obex)
			OBEX_Cleanup(data->obex);
		data->obex = data->funcs->init(data->arg, eventcb);
	}
	if (data->obex) {
		int fd = OBEX_GetFD(data->obex);
		if (fd >= 0)
		  (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
		OBEX_SetUserData(data->obex, data);
	}
	if ((data->auth_level & AUTH_LEVEL_TRANSPORT) &&
	    data->funcs && data->funcs->security_init)
	{
		data->funcs->security_init(data->arg, data->obex);
	}
}

uint8_t net_security_init (
	struct net_data* data,
	struct auth_handler* auth,
	obex_object_t* obj
)
{
	if ((data->auth_level & AUTH_LEVEL_TRANSPORT) &&
	    data->funcs && data->funcs->security_check &&
	    !data->funcs->security_check(data->arg, data->obex))
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

	return OBEX_RSP_CONTINUE;
}

void net_security_cleanup (struct net_data* data)
{
	if (data->funcs && data->funcs->security_cleanup)
		data->funcs->security_cleanup(data->arg);
}

int net_security_check (struct net_data* data)
{
	int transport = 1;
	int obex = 1;

	if ((data->auth_level & AUTH_LEVEL_TRANSPORT) &&
	    data->funcs && data->funcs->security_check)
		transport = data->funcs->security_check(data->arg, data->obex);

	if ((data->auth_level & AUTH_LEVEL_OBEX))
		obex = data->auth_success;

	return transport && obex;
}

void net_get_peer (struct net_data* data, char* buffer, size_t bufsiz)
{
	if (data->funcs && data->funcs->get_peer)
		data->funcs->get_peer(data->obex, buffer, bufsiz);	
}

void net_cleanup (struct net_data* data)
{
	net_security_cleanup(data);
	if (data->funcs && data->funcs->cleanup)
		data->funcs->cleanup(data->arg, data->obex);
	if (data->obex) {
		OBEX_Cleanup(data->obex);
		data->obex = NULL;
	}
}
