
#include "net/core.h"

struct net_data {
	void* arg;
	obex_t* obex;
	struct net_funcs* funcs;
};
struct net_data* net_data_new ();
void net_init (struct net_data* data, obex_event_t eventcb);
void net_security_init (struct net_data* data);
void net_security_cleanup (struct net_data* data);
void net_cleanup (struct net_data* data);

#if OPENOBEX_TCPOBEX
int tcp_setup(struct net_data*, const char*, uint16_t, const char*);
#else /* OPENOBEX_TCPOBEX */
int inet_setup(struct net_data* data);
#define tcp_setup(data, addr, port, intf) inet_setup(data)
#endif /* OPENOBEX_TCPOBEX */

int bluetooth_setup(struct net_data*, uint8_t);

int irda_setup(struct net_data*, char*);