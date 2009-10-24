#include "../obex_auth.h"

int obex_auth_add_challenges (
	obex_t* handle,
	obex_object_t* obj,
	const struct obex_auth_challenge* chal,
	unsigned int count
);

int obex_auth_unpack_response (
	const obex_headerdata_t h,
	uint32_t size,
	struct obex_auth_response* resp
);

int obex_auth_check_response (
	const struct obex_auth_response* resp,
	const uint8_t* pass,
	size_t len
);

int obex_auth_unpack_challenge (
	const obex_headerdata_t h,
	uint32_t hsize,
	struct obex_auth_challenge* chal, /*array*/
	size_t csize
);

int obex_auth_challenge2response (
	obex_t* handle,
	struct obex_auth_response* r,
	const struct obex_auth_challenge* c,
	const uint8_t *user, size_t ulen,
	const uint8_t *pass, size_t plen
);

int obex_auth_add_response (
	obex_t* handle,
	obex_object_t* obj,
	const struct obex_auth_response* resp
);
