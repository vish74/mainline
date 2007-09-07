#include <inttypes.h>
/* not needed here but needed if you ever need bluetooth elsewhere */
#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>

#define OBEX_AUTH_OPT_USER_REQ (1 << 0) /* request user identifier */
#define OBEX_AUTH_OPT_FULL_ACC (1 << 1) /* full access can be granted */

struct obex_auth_challenge {
	uint8_t nonce[16];
	uint8_t opts;
	
	/* zero-terminated,
	 * host byte order
	 * malloc'd
	 */
	uint16_t* realm;
};

struct obex_auth_response {
	uint8_t digest[16];
	uint8_t nonce[16];

	/* variable but limited length */
	uint8_t user[20];
	size_t ulen;
};

/* get user and password according to realm */
typedef void (*obex_auth_pass_t) (
	obex_t* handle,
	const char* realm, /* UTF-8 */
	/*@out@*/ char* user,
	size_t* ulen,
	/*@out@*/ char* pass,
	size_t* plen
);

int obex_auth_add_challenge (
	obex_t* handle,
	obex_object_t* obj,
	struct obex_auth_challenge* chal
);

int obex_auth_unpack_response (
	obex_headerdata_t h,
	uint32_t size,
	/*@out@*/ struct obex_auth_response* resp
);

int obex_auth_check_response (
	struct obex_auth_response* resp,
	const uint8_t* pass,
	size_t len
);

int obex_auth_unpack_challenge (
	obex_headerdata_t h,
	uint32_t hsize,
	struct obex_auth_challenge* chal, /*array*/
	size_t csize
);

int obex_auth_challenge2response (
	obex_t* handle,
	struct obex_auth_challenge* c,
	struct obex_auth_response* r,
	obex_auth_pass_t get_pass
);

int obex_auth_add_response (
	obex_t* handle,
	obex_object_t* obj,
	struct obex_auth_response* resp
);
