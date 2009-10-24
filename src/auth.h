#include <inttypes.h>
#include <openobex/obex.h>
#include "obex_auth.h"

#ifndef OBEXPUSHD_AUTH_H
#define OBEXPUSHD_AUTH_H

typedef int (*auth_verify_cb)(void*, const uint8_t *pass, size_t plen);

struct auth_handler;
struct auth_handler_ops {
	/** Get the number or realm available by this handler
	 *
	 * @return number of available realms or a negative error number
	 */
	int (*get_realm_count)(struct auth_handler *self);

	/** Get the realm name
	 *
	 * @param id a zero based sequential value
	 * @return an UCS-2 encoded string
	 */
	const uint16_t* (*get_realm_name)(struct auth_handler *self,
					  int id);

	/** Get the challenge options that are valid for a realm
	 *
	 * @param realm the realm
	 * @return a bitfields with the allowed OBEX_AUTH_OPT_* bits set
	 */
	uint8_t (*get_realm_opts)(struct auth_handler *self,
				  const uint16_t *realm);

	/** Verify a user/password pair in a given realm
	 *
	 * @param realm the realm to verify in
	 * @param user the user value (no format implied)
	 * @param ulen size of the user data
	 * @param cb callback function to verify the password
	 * @param cb_data the first argument for cb
	 * @return 0 is verification failed, else 1
	 */
	int (*verify)(struct auth_handler *self,
		      const uint16_t *realm,
		      const uint8_t *user, size_t ulen,
		      auth_verify_cb cb, void *cb_data);

	struct auth_handler* (*copy)(struct auth_handler *self);
	void (*cleanup)(struct auth_handler *self);
};

enum auth_state {
	AUTH_STATE_NONE = 0,
	AUTH_STATE_REQUEST_SENT,
	AUTH_STATE_SUCCESS,
};

struct auth_handler {
	struct auth_handler_ops *ops;
	enum auth_state state;
	struct {
		uint8_t nonce[16];
	} *session;
	void *private_data;
};

struct auth_handler* auth_file_init (char* file, uint16_t *realm, uint8_t opts);
struct auth_handler* auth_copy (struct auth_handler *h);
void auth_destroy (struct auth_handler *h);

int auth_init (struct auth_handler *self, obex_t *handle, obex_object_t *obj);
int auth_verify (struct auth_handler *self, obex_headerdata_t h, uint32_t size);

#endif /* OBEXPUSHD_AUTH_H */
