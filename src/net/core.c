#include "net.h"
#include <obex_auth.h>

#include <stdlib.h>

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
		OBEX_SetUserData(data->obex, data);
	}
}

void net_security_init (
	struct net_data* data,
	obex_object_t* obj
)
{
	if (data->funcs && data->funcs->security_init)
		data->funcs->security_init(data->arg);

	else {
		struct obex_auth_challenge chal;
		if (get_nonce(chal.nonce) < 0)
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_SERVICE_UNAVAILABLE,
						OBEX_RSP_SERVICE_UNAVAILABLE);
		memcpy(data->nonce, chal.nonce, sizeof(data->nonce));
		chal.opts = (OBEX_AUTH_OPT_USER_REQ | OBEX_AUTH_OPT_FULL_ACC);
		chal.realm = NULL;
		(void)obex_auth_add_challenge(data->obex, obj, &chal);
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_UNAUTHORIZED,
					OBEX_RSP_UNAUTHORIZED);
	}
}

void net_security_cleanup (struct net_data* data)
{
	if (data->funcs && data->funcs->security_cleanup)
		data->funcs->security_cleanup(data->arg);
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
