/* Copyright (C) 2006-2007 Hendrik Sattler <post@hendrik-sattler.de>
 *       
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.		       
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *	       
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */
   
#include "auth.h"
#include "obex_auth.h"
#include "io.h"
#include "utf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

#include "compiler.h"

struct auth_handler* auth_copy (struct auth_handler *h)
{
	if (!h)
		return NULL;

	if (h->ops && h->ops->copy) {
		/* deep copy */
		return h->ops->copy(h);

	} else {
		/* flat copy */
		struct auth_handler *hnew = malloc(sizeof(*h));
		if (hnew) {
			int count = 0;
			if (h->ops && h->ops->get_realm_count)
				count = h->ops->get_realm_count(h);
			memcpy(hnew, h, sizeof(*h));
			hnew->session = calloc(count, sizeof(*hnew->session));
			if (!hnew->session) {
				free(hnew);
				hnew = NULL;
			}
		}
		return hnew;
	}
}

void auth_destroy (struct auth_handler* h)
{
	if (h) {
		if (h->ops && h->ops->cleanup)
			h->ops->cleanup(h);
		free(h);
	}
}

static int auth_get_nonce (uint8_t nonce[16])
{
#if defined(USE_LIBGCRYPT)
	gcry_create_nonce(nonce, 16);
	return 0;

#else
#define RANDOM_FILE "/dev/urandom"
	int status;
	int fd = open(RANDOM_FILE, O_RDONLY);

	if (fd < 0)
		return -errno;
	status = (int)read(fd, nonce, 16);
	(void)close(fd);

	if (status < 0)
		return -errno;
	else if (status != 16)
		return -EIO;
	else
		return 0;
#endif
}

int auth_init (struct auth_handler *self, obex_t *handle, obex_object_t *obj)
{
	struct obex_auth_challenge *chal;
	int count = 0;
	int i;

	if (!(self && self->ops && self->ops->get_realm_count))
		return 0;

	count = self->ops->get_realm_count(self);
	if (count == 0)
		return 0;

	switch (self->state) {
	case AUTH_STATE_NONE:
		for (i = 0; i < count; ++i) {
			if (auth_get_nonce(self->session[i].nonce) < 0)
				return 0;
		}
		self->state = AUTH_STATE_REQUEST_SENT;
		/* no break */

	case AUTH_STATE_REQUEST_SENT:
		chal = calloc(count, sizeof(*chal));
		if (!chal)
			return 0;
		for (i = 0; i < count; ++i) {
			memcpy(chal[i].nonce, self->session[i].nonce, sizeof(chal->nonce));
			if (self->ops && self->ops->get_realm_name) {
				const uint16_t *r = self->ops->get_realm_name(self, i);
				chal[i].realm.data = r;
				chal[i].realm.len = ucs2len(r) * sizeof(*r);
				chal[i].realm.charset = 0xFF;
			}
			if (self->ops && self->ops->get_realm_opts)
				chal[i].opts = self->ops->get_realm_opts(self, chal[i].realm.data);
		}
		(void)OBEX_AuthAddChallenges(handle, obj, chal, count);
		free(chal);
		/* no break */
		
	case AUTH_STATE_SUCCESS:
		return 1;
	}
	
	return 1;
}

static int obex_auth_verify_cb(void* resp, const uint8_t *pass, size_t plen)
{
	return OBEX_AuthCheckResponse(resp, pass, plen);
}

int auth_verify (struct auth_handler *self,
		 obex_headerdata_t h,
		 uint32_t size)
{
	struct obex_auth_response resp;
	int count = 0;
	int i;

	switch (self->state) {
	case AUTH_STATE_NONE:
	default:
		return 0;

	case AUTH_STATE_REQUEST_SENT:
		if (!(self && self->ops && self->ops->verify))
			return 0;
		if (self->ops->get_realm_count)
			count = self->ops->get_realm_count(self);
		if (count == 0)
			return 0;
		memset(&resp,0,sizeof(resp));
		if (OBEX_AuthUnpackResponse(h,size,&resp) < 0)
			return 0;
		for (i = 0; i < count; ++i) {
			if (memcmp(self->session[i].nonce, resp.nonce, sizeof(resp.nonce)) == 0)
			{
				if (!self->ops->verify(self,
						       self->ops->get_realm_name(self, i),
						       resp.user, resp.ulen,
						       obex_auth_verify_cb, &resp))
				{
					return 0;
				}
			}
		}
		self->state = AUTH_STATE_SUCCESS;
		/* no break */

	case AUTH_STATE_SUCCESS:
		return 1;
	}
}
