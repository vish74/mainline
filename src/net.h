
#ifndef OBEXPUSHD_NET_H
#define OBEXPUSHD_NET_H

#include "net/core.h"
#include "auth.h"

struct net_handler;
struct net_handler_ops {
	obex_t* (*init)(struct net_handler*, obex_event_t);
	void (*cleanup)(struct net_handler*);

	/* Functions to implement authentication
	 */
	int (*security_init)(struct net_handler*, obex_t*);
	int (*security_check)(struct net_handler*, obex_t*);

	/* Writes the peer address string
	 *   "<protocol>/[<numeric address>]\0"
         * to buffer and cuts at bufsiz.
         * The return value is the valid length of buffer
	 * or a negated error number (see errno) on error.
	 */
	int  (*get_peer)(struct net_handler*, obex_t*, char* buffer, size_t bufsiz);

	void (*disconnect)(struct net_handler*, obex_t*);
};

struct net_handler {
	struct net_handler_ops* ops;
	void* args;
};
struct net_handler* net_handler_alloc(struct net_handler_ops *ops, size_t argsize);
void net_handler_cleanup(struct net_handler*);

struct net_handler* bluetooth_setup(char* device_addr, uint8_t);
struct net_handler* irda_setup(char*);
#if OPENOBEX_TCPOBEX
struct net_handler* tcp_setup(const char*, uint16_t);
#else /* OPENOBEX_TCPOBEX */
struct net_handler* inet_setup();
#endif /* OPENOBEX_TCPOBEX */


struct net_data {
	obex_t* obex;
	struct net_handler *handler;

	/* auth */
	int auth_success;
#define AUTH_LEVEL_OBEX      (1 << 0)
#define AUTH_LEVEL_TRANSPORT (1 << 1)
	uint8_t auth_level;
};
struct net_data* net_data_new ();
void net_init (struct net_data* data, obex_event_t eventcb);
uint8_t net_security_init (
	struct net_data* data,
	struct auth_handler* auth,
	obex_object_t* obj
);
int net_security_check (struct net_data* data);
void net_security_cleanup (struct net_data* data);
void net_get_peer (struct net_data* data, char* buffer, size_t bufsiz);
void net_disconnect (struct net_data* data);
void net_cleanup (struct net_data* data);

#endif /* OBEXPUSHD_NET_H */
