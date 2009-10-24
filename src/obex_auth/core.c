#include "obex_auth.h"

#include "stdlib.h"
#include "errno.h"

/* remove this define when moving the code to openobex */
#define obex_return_val_if_fail(test, val)	do { if (!(test)) return val; } while(0);

/**
	Add the OBEX authentication challenge header
	\param self OBEX handle
	\param object OBEX object
	\param chal authentication challenge data
	\return 0 on success, else a negative error code value
 */
int OBEX_AuthAddChallenges(obex_t *self, obex_object_t *object,
			   const struct obex_auth_challenge *chal,
			   unsigned int count)
{
	obex_return_val_if_fail(self != NULL, -EINVAL);
	obex_return_val_if_fail(object != NULL, -EINVAL);
	obex_return_val_if_fail(chal != NULL, -EINVAL);
	return obex_auth_add_challenges(self, object, chal, count);
}

/**
	Unpack the OBEX authentication reponse header
	\param h header data that contains the response header
	\param size size of the header data
	\param resp where to write the unpacked data to
	\return 0 on success, else a negative error code value
 */
int OBEX_AuthUnpackResponse(const obex_headerdata_t h, uint32_t size,
			    struct obex_auth_response *resp)
{
	obex_return_val_if_fail(resp != NULL, -EINVAL);
	return obex_auth_unpack_response(h, size, resp);
}

/**
	Check the obex authentication reponse
	\param resp the OBEX authentication response data
	\param pass the password to check against
	\param len length of pass
	\return 1 on success, 0 on failure
 */
int OBEX_AuthCheckResponse(const struct obex_auth_response *resp,
			   const uint8_t *pass, size_t len)
{
	obex_return_val_if_fail(resp != NULL, 0);
	return obex_auth_check_response(resp, pass, len);
}

/**
	Unpack the OBEX authentication challenge header
	\param h header data that contains the response header
	\param hsize size of the header data
	\param chal where to write the unpacked data to (array)
	\param csize array size of chal
	\return number of successfully unpacked challenges, else a negative error code value
 */
int OBEX_AuthUnpackChallenge(const obex_headerdata_t h, uint32_t hsize,
			     struct obex_auth_challenge *chal,
			     size_t csize)
{
	obex_return_val_if_fail(chal != NULL, -EINVAL);
	return obex_auth_unpack_challenge(h, hsize, chal, csize);
}

/**
	Process a challenge and get the reponse
	\param self OBEX handle
	\param chal OBEX authentication challenge data
	\param resp where to write the OBEX authentication response data to
	\param get_pass callback to get the password from
	\return 0 on success, else a negative error code value
 */
int OBEX_AuthChallenge2Response(obex_t *self,
				struct obex_auth_response *resp,
				const struct obex_auth_challenge *chal,
				const uint8_t *user, size_t ulen,
				const uint8_t *pass, size_t plen)
{
	obex_return_val_if_fail(self != NULL, -EINVAL);
	obex_return_val_if_fail(resp != NULL, -EINVAL);
	obex_return_val_if_fail(chal != NULL, -EINVAL);
	obex_return_val_if_fail(!user && ulen, -EINVAL);
	obex_return_val_if_fail(!pass && plen, -EINVAL);
	return obex_auth_challenge2response(self, resp, chal, user, ulen, pass, plen);
}

/**
	Add the OBEX authentication response header
	\param self OBEX handle
	\param object OBEX object
	\param resp authentication response data
	\return 0 on success, else a negative error code value
 */
int OBEX_AuthAddResponse(obex_t *self, obex_object_t *object,
			 const const struct obex_auth_response *resp)
{
	obex_return_val_if_fail(self != NULL, -EINVAL);
	obex_return_val_if_fail(object != NULL, -EINVAL);
	obex_return_val_if_fail(resp != NULL, -EINVAL);
	return obex_auth_add_response(self, object, resp);
}
