#include <inttypes.h>
#include <openobex/obex.h>

#ifndef OBEX_AUTH_H
#define OBEX_AUTH_H

#define OBEX_AUTH_OPT_USER_REQ (1 << 0) /* request user identifier */
#define OBEX_AUTH_OPT_FULL_ACC (1 << 1) /* full access can be granted */

/** OBEX authentication challenge data
 */
struct obex_auth_challenge {
	/** NONCE value */
	uint8_t nonce[16];

	/** options, see OBEX_AUTH_OPT_* */
	uint8_t opts;

	/** zero-terminated 16bit unicode string
	 * This must be in host byte order and if filled by an OBEX_Auth*
	 * function, it was malloc'd.
	 */
	const uint16_t* realm;
};

/** OBEX authentication response data
 */
struct obex_auth_response {
	/** MD5 digest value */
	uint8_t digest[16];

	/** NONCE value */
	uint8_t nonce[16];

	/** user identification value */
	const uint8_t *user;

	/** number of valid bytes in the 'user' field */
	size_t ulen;
};

/*
 * OBEX authentication helper
 */
int OBEX_AuthAddChallenges(obex_t *self, obex_object_t *object,
			   const struct obex_auth_challenge *chal,
			   unsigned int count);
int OBEX_AuthUnpackResponse(const obex_headerdata_t h, uint32_t size,
			    struct obex_auth_response *resp);
int OBEX_AuthCheckResponse(const struct obex_auth_response *resp,
			   const uint8_t *pass, size_t len);
int OBEX_AuthUnpackChallenge(const obex_headerdata_t h, uint32_t hsize,
			     struct obex_auth_challenge *chal,
			     size_t csize);
int OBEX_AuthChallenge2Response(obex_t *self,
				struct obex_auth_response *resp,
				const struct obex_auth_challenge *chal,
				const uint8_t *user, size_t ulen,
				const uint8_t *pass, size_t plen);
int OBEX_AuthAddResponse(obex_t *self, obex_object_t *object,
			 const struct obex_auth_response *resp);

#endif /* OBEX_AUTH_H */
