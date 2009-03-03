/* Copyright (C) 2006 Hendrik Sattler <post@hendrik-sattler.de>
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
#include "utf.h"
#include <openobex/obex.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

static
void obex_auth_calc_digest (/*@out@*/ uint8_t digest[16],
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

static size_t strlen16 (uint16_t* s) {
	size_t n = 0;
	if (s != 0)
		while (s[n] != 0x0000) ++n;
	return n;
}

/* Function for an OBEX server.
 */
int obex_auth_add_challenge (obex_t* handle,
			     obex_object_t* obj,
			     struct obex_auth_challenge* chal)
{
	int err = 0;
	obex_headerdata_t ah;
        uint8_t* ptr;
	size_t len = strlen16(chal->realm);

	ah.bs = malloc(2 + sizeof(chal->nonce) + 3 + 3 + 2*(len+1));
	if (!ah.bs)
		return -ENOMEM;
	ptr = (uint8_t*)ah.bs;

	/* add nonce */
	*ptr++ = 0x00;
	*ptr++ = sizeof(chal->nonce);
	memcpy(ptr,chal->nonce,sizeof(chal->nonce));
	ptr += sizeof(chal->nonce);

	/* add flags */
	*ptr++ = 0x01;
	*ptr++ = 0x01;
	*ptr++ = chal->opts;

	/* add realm */
	if (chal->realm != NULL && len != 0) {
		size_t i = 0;

		*ptr++ = 0x02;
		*ptr++ = 2*len+1;
		*ptr++ = 0xFF;
		for (; i < len+1; ++i)
			((uint16_t *)ptr)[i] = htons(chal->realm[i]);
		ptr += 2*i;
	}

	errno = 0;
	if (OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_AUTHCHAL,ah,(uint32_t)(ptr-ah.bs),OBEX_FL_FIT_ONE_PACKET) < 0)
		err = ((errno != 0)? -errno: -EINVAL);
	free((void*)ah.bs);
	return err;
}

int obex_auth_unpack_response (obex_headerdata_t h,
			       uint32_t size,
			       struct obex_auth_response* resp)
{
	uint32_t i = 0;
	for (; i < size; i += h.bs[i+1]+2) {
		uint8_t htype = h.bs[i];
		uint8_t hlen = h.bs[i+1];
		const uint8_t* hdata = h.bs+(i+2);

		switch (htype){
		case 0x00: /* digest */
			if (hlen != sizeof(resp->digest))
				return -1;
			memcpy(resp->digest,hdata,sizeof(resp->digest));
			break;

		case 0x01: /* user ID */
			if ((size_t)hlen > sizeof(resp->user))
				return -1;
			memcpy(resp->user,hdata,hlen);
			resp->ulen = (size_t)hlen;
			break;

		case 0x02: /* nonce */
			if (hlen != sizeof(resp->nonce))
				return -1;
			memcpy(resp->nonce,hdata,sizeof(resp->nonce));
			break;

		default:
			return -1;
		}
	}
	return 0;
}

int obex_auth_check_response (struct obex_auth_response* resp,
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
int obex_auth_unpack_challenge (obex_headerdata_t h,
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
		const uint8_t* hdata = h.bs+(i+2);

		switch (htype){
		case 0x00: /* nonce */
			if (k >= csize)
				return k;
			if (hlen != 16)
				return -1;
			++k;
			memcpy(chal[k].nonce,hdata,16);
			break;

		case 0x01: /* options */
			if (hlen != 1)
				return -1;
			chal[k].opts = *hdata;
			break;

		case 0x02: /* realm */
			if (*hdata != 0xFF) /* only support unicode */
				return -1;

			if (chal[k].realm != NULL)
				return -1;

			--hlen;
			++hdata;
			
			if (hdata[hlen] != 0x00 ||
			    hdata[hlen-1] != 0x00)
				chal[k].realm = malloc(hlen+2);
			else
				chal[k].realm = malloc(hlen);
			memset(chal[k].realm, 0, rsize);

			hlen /= 2;
			for (rsize=0; rsize < hlen; ++rsize)
				chal[k].realm[rsize] = ntohs(((uint16_t *)hdata)[rsize]);
			break;

		default:
			return -1;
		}
	}
	return k;
}

int obex_auth_challenge2response (obex_t* handle,
				  struct obex_auth_challenge* c,
				  struct obex_auth_response* r,
				  obex_auth_pass_t get_pass)
{
	uint8_t pass[32];
	size_t plen;

	memcpy(r->nonce, c->nonce, sizeof(r->nonce));
	get_pass(handle, c->realm, (char*)r->user, &r->ulen, (char*)pass, &plen);
	if (r->ulen > sizeof(r->user) ||
	    plen > sizeof(pass))
		return 0;
	obex_auth_calc_digest(r->digest, r->nonce, pass, plen);
	memset(pass, 0, sizeof(pass));
	if ((c->opts & OBEX_AUTH_OPT_USER_REQ) != 0)
		r->ulen = 0;

	return 1;
}

int obex_auth_add_response (obex_t* handle,
			    obex_object_t* obj,
			    struct obex_auth_response* resp)
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
