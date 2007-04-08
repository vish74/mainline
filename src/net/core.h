#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>

struct net_funcs {
	obex_t* (*init)(void*, obex_event_t);
	void (*cleanup)(void*, obex_t*);
	void (*security_init)(void*);
	void (*security_cleanup)(void*);
};
