#include <inttypes.h>
#include <openobex/obex.h>

#define OBEX_AUTH_OPT_USER_REQ (1 << 0) /* request user identifier */
#define OBEX_AUTH_OPT_FULL_ACC (1 << 1) /* full access can be granted */

/* realm must be in host byte order
 */
int obex_auth_add_challenge (obex_t* handle,
			     obex_object_t* obj,
			     uint8_t nonce[16],
			     uint8_t opts,
			     /*@null@*/uint16_t* realm);

int obex_auth_unpack_response (obex_headerdata_t h,
			       uint32_t size,
			       /*@out@*/ uint8_t digest[16],
			       /*@out@*/ uint8_t nonce[16],
			       /*@out@*/ uint8_t user[20]);

int obex_auth_check_response (uint8_t digest[16],
			      const uint8_t nonce[16],
 			      const uint8_t* pass,
			      size_t len);

int obex_auth_add_response (obex_t* handle,
			    obex_object_t* obj,
			    uint8_t nonce[16],
			    const /*@null@*/ uint8_t* user,
			    size_t ulen,
			    const uint8_t* pass,
			    size_t plen);

/* realm will be in host byte order
 * return number or characters in realm
 */
int obex_auth_unpack_challenge (obex_headerdata_t h,
				uint32_t size,
				/*@out@*/ uint8_t nonce[16],
				/*@out@*/ uint8_t* opts,
				/*@out@*/ uint16_t* realm,
				size_t realm_size);
