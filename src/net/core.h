#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>

struct net_funcs {
	obex_t* (*init)(void*, obex_event_t);
	void (*cleanup)(void*, obex_t*);

	/* Functions to implement authentication
	 */
	void (*security_init)(void*);
	void (*security_cleanup)(void*);

	/* Writes the peer address string
	 *   "<protocol>/[<numeric address>]\0"
         * to buffer and cuts at bufsiz.
         * The return value is the valid length of buffer
	 * or a negated error number (see errno) on error.
	 */
	int  (*get_peer)(obex_t*, char* buffer, size_t bufsiz);
};

int get_nonce (/*@out@*/ uint8_t nonce[16]);
