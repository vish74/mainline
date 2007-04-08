#include "net.h"

#include <stdlib.h>

struct net_data* net_data_new ()
{
	struct net_data* data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	data->arg = NULL;
	data->obex = NULL;
	data->funcs = NULL;
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
}

void net_security_init (struct net_data* data)
{
	if (data->funcs && data->funcs->security_init)
		data->funcs->security_init(data->arg);
}

void net_security_cleanup (struct net_data* data)
{
	if (data->funcs && data->funcs->security_cleanup)
		data->funcs->security_cleanup(data->arg);
}

void net_cleanup (struct net_data* data)
{
	net_security_cleanup(data);
	if (data->funcs && data->funcs->cleanup)
		data->funcs->cleanup(data->arg, data->obex);
}
