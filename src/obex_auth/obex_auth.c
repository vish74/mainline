/* Copyright (C) 2006-2008 Hendrik Sattler <post@hendrik-sattler.de>
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
   
#include "obex_auth.h"
#include "md5.h"

#if !defined(_WIN32)
#include "arpa/inet.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

static
void obex_auth_calc_digest (uint8_t digest[16],
                            const uint8_t nonce[16],
                            const uint8_t* pass,
                            size_t len)
{
	struct MD5Context context;

	MD5Init(&context);
	MD5Update(&context, nonce, 16);
	MD5Update(&context, (uint8_t*)":", 1);
	MD5Update(&context, pass, len);
	MD5Final(digest, &context);
}

static
size_t strlen16 (const uint16_t* s) {
	size_t n = 0;
	if (s != 0)
		while (s[n] != 0x0000) ++n;
	return n;
}

/* Function for an OBEX server.
 */
int obex_auth_add_challenges (obex_t* handle,
			      obex_object_t* obj,
			      const struct obex_auth_challenge* chal,
			      unsigned int count)
{
	int err = 0;
	obex_headerdata_t ah;
	uint8_t* ptr;
	unsigned int realm_check = 1;
	uint32_t total = 0;
	unsigned int i;
	
	for (i = 0; i < count; ++i) {
		total += 2 + sizeof(chal[0].nonce);
		if (chal[i].opts)
			total += 3;
		if (chal[i].realm) {
			size_t len = strlen16(chal[i].realm);
			if (len)
				total += 3 + 2*(len+1);
		} else {
			if (--realm_check == 0)
				return -EINVAL;
		}
	}
	ptr = malloc(total);
	if (!ptr)
		return -ENOMEM;

	for (i = 0; i < count; ++i) {
		/* add nonce */
		*ptr++ = 0x00;
		*ptr++ = sizeof(chal[0].nonce);
		memcpy(ptr, chal[0].nonce, sizeof(chal[0].nonce));
		ptr += sizeof(chal[0].nonce);

		if (chal[i].opts) {
			/* add flags */
			*ptr++ = 0x01;
			*ptr++ = 0x01;
			*ptr++ = chal[i].opts;
		}

		/* add realm */
		if (chal[i].realm) {
			size_t len = strlen16(chal[i].realm);
			if (len) {
				size_t k = 0;

				*ptr++ = 0x02;
				*ptr++ = 2*len+1;
				*ptr++ = 0xFF;
				for (; k < len+1; ++k)
					((uint16_t *)ptr)[k] = htons(chal[i].realm[k]);
				ptr += 2*k;
			}
		}
	};

	ah.bs = ptr;
	errno = 0;
	if (0 > OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_AUTHCHAL, ah,
				     (uint32_t)(ptr-ah.bs),
				     OBEX_FL_FIT_ONE_PACKET))
		err = ((errno != 0)? -errno: -EINVAL);
	ah.bs = NULL;
	free(ptr);

	return err;
}

int obex_auth_unpack_response (const obex_headerdata_t h,
                               uint32_t size,
                               struct obex_auth_response* resp)
{
	uint32_t i = 0;
	for (; i < size; i += h.bs[i+1]+2) {
		uint8_t htype = h.bs[i];
		uint8_t hlen = h.bs[i+1];
		const uint8_t* hdata = h.bs+i+2;

		switch (htype){
		case 0x00: /* digest */
			if (hlen != sizeof(resp->digest))
				return -EINVAL;
			memcpy(resp->digest,hdata,sizeof(resp->digest));
			break;

		case 0x01: /* user ID */
		{
			uint8_t *user = malloc(hlen);
			if (!user)
				return -ENOMEM;
			memcpy(user,hdata,hlen);
			resp->user = user;
			resp->ulen = (size_t)hlen;
			break;
		}

		case 0x02: /* nonce */
			if (hlen != sizeof(resp->nonce))
				return -EINVAL;
			memcpy(resp->nonce,hdata,sizeof(resp->nonce));
			break;

		default:
			return -EINVAL;
		}
	}
	return 0;
}

int obex_auth_check_response (const struct obex_auth_response* resp,
                              const uint8_t* pass,
                              size_t len)
{
	uint8_t d[16];

	memset(d,0,sizeof(d));
	obex_auth_calc_digest(d,resp->nonce,pass,len);
	if (memcmp(d,resp->digest,sizeof(d)) != 0)
		return 0;

	return 1;
}


/* Functions for an OBEX client.
 */
int obex_auth_unpack_challenge (const obex_headerdata_t h,
                                uint32_t hsize,
                                struct obex_auth_challenge* chal,
                                size_t csize)
{
	uint32_t i = 0;
	size_t k = 0;
	size_t rsize = 0;

	for (; i < hsize; i += h.bs[i+1]+2) {
		uint8_t htype = h.bs[i];
		size_t hlen = h.bs[i+1];
		const uint8_t* hdata = h.bs+i+2;
		uint16_t *r = NULL;;

		switch (htype){
		case 0x00: /* nonce */
			if (k >= csize)
				return k;
			if (hlen != 16)
				return -EINVAL;
			++k;
			memcpy(chal[k].nonce,hdata,16);
			break;

		case 0x01: /* options */
			if (hlen != 1)
				return -EINVAL;
			chal[k].opts = *hdata;
			break;

		case 0x02: /* realm */
			if (*hdata != 0xFF) /* only support unicode */
				return -ENOTSUP;

			if (chal[k].realm != NULL) {
				uint16_t *r = (uint16_t *)chal[k].realm;
				chal[k].realm = NULL;
				free(r);
			}

			--hlen;
			++hdata;

			if (hdata[hlen] != 0x00 ||
			    hdata[hlen-1] != 0x00)
				rsize = hlen+2;
			else
				rsize = hlen;
			r = malloc(rsize);
			memset(r, 0, rsize);
			hlen /= 2;
			for (rsize=0; rsize < hlen; ++rsize)
				r[rsize] = ntohs(((uint16_t *)hdata)[rsize]);
			chal[k].realm = r;
			break;

		default:
			return -EINVAL;
		}
	}
	return k;
}

int obex_auth_challenge2response (obex_t* handle,
                                  struct obex_auth_response* r,
                                  const struct obex_auth_challenge* c,
				  const uint8_t *user, size_t ulen,
				  const uint8_t *pass, size_t plen)
{
	memcpy(r->nonce, c->nonce, sizeof(r->nonce));
	obex_auth_calc_digest(r->digest, r->nonce, pass, plen);
	if (c->opts & OBEX_AUTH_OPT_USER_REQ) {
		uint8_t *u = malloc(ulen);
		if (!u)
			return -ENOMEM;
		memcpy(u, user, ulen);
		r->user = u;
		r->ulen = ulen;
	} else {
		r->user = NULL;
		r->ulen = 0;
	}

	return 0;
}

int obex_auth_add_response (obex_t* handle,
                            obex_object_t* obj,
                            const struct obex_auth_response* resp)
{
	int err = 0;
	obex_headerdata_t ah;
	uint8_t* ptr;

	ah.bs = malloc(2+sizeof(resp->digest) + 2+resp->ulen + 2+sizeof(resp->nonce));
	if (!ah.bs)
		return -ENOMEM;
	ptr = (uint8_t*)ah.bs;

	/* add digest */
	*ptr++ = 0x00;
	*ptr++ = sizeof(resp->digest);
	memcpy(ptr,resp->digest,sizeof(resp->digest));
	ptr += sizeof(resp->digest);

	/* add user */
	if (resp->ulen) {
		*ptr++ = 0x01;
		*ptr++ = resp->ulen;
		memcpy(ptr,resp->user,resp->ulen);
		ptr += resp->ulen;
	}

	/* add nonce */
	*ptr++ = 0x00;
	*ptr++ = sizeof(resp->nonce);
	memcpy(ptr,resp->nonce,sizeof(resp->nonce));
	ptr += sizeof(resp->nonce);

	errno = 0;
	if (0 > OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_AUTHRESP, ah,
				     (uint32_t)(ptr-ah.bs),
				     OBEX_FL_FIT_ONE_PACKET))
		err = ((errno != 0)? -errno: -EINVAL);
	free((void*)ah.bs);
	return err;
}
