
#include "net/core.h"

struct net_data {
	void* arg;
	obex_t* obex;
	struct net_funcs* funcs;

	/* auth */
	uint8_t nonce[16];
	int auth_success;
};
struct net_data* net_data_new ();
void net_init (struct net_data* data, obex_event_t eventcb);
uint8_t net_security_init (
	struct net_data* data,
	obex_object_t* obj
);
void net_security_cleanup (struct net_data* data);
void net_get_peer (struct net_data* data, char* buffer, size_t bufsiz);
void net_cleanup (struct net_data* data);

#if OPENOBEX_TCPOBEX
int tcp_setup(struct net_data*, const char*, uint16_t);
#else /* OPENOBEX_TCPOBEX */
int inet_setup(struct net_data* data);
#endif /* OPENOBEX_TCPOBEX */

int bluetooth_setup(struct net_data*, char* device_addr, uint8_t);

int irda_setup(struct net_data*, char*);
