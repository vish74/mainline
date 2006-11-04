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

static
void obex_auth_calc_digest (/* out */ uint8_t digest[16],
			    const uint8_t nonce[16],
			    const uint8_t* pass,
			    size_t len)
{
	uint8_t* tmp;
	size_t tmp_size;

	/* assemble digest cleartext */
	tmp_size = sizeof(nonce)+1+strlen((char*)pass);
	tmp = malloc(tmp_size);
	if (!tmp)
		return;
	memcpy(tmp,nonce,sizeof(nonce));
	tmp[sizeof(nonce)] = ':';
	memcpy(tmp+sizeof(nonce)+1,pass,len);

	/* calculate digest hash */
	MD5(digest,tmp,tmp_size);
	free(tmp);
}


/* Function for an OBEX server.
 */
int obex_auth_add_challenge (obex_t* handle,
			     obex_object_t* obj,
			     uint8_t nonce[16],
			     uint8_t opts,
			     uint16_t* realm)
{
	obex_headerdata_t ah;
        uint8_t* ptr;
	size_t len = utf16len(realm);

	ah.bs = malloc(2+16 + 3 + 2+2*(len+1));
	if (!ah.bs)
		return -ENOMEM;
	ptr = (uint8_t*)ah.bs;

	/* add nonce */
	*ptr++ = 0x00;
	*ptr++ = 16;
	memcpy(ptr,nonce,16);
	ptr += 16;

	/* add flags */
	*ptr++ = 0x01;
	*ptr++ = 0x01;
	*ptr++ = opts;

	/* add realm */
	if (len) {
		++len;
		*ptr++ = 0x02;
		*ptr++ = 2*len+1;
		*ptr++ = 0xFF;
		memcpy(ptr,realm,2*len);
		ucs2_hton((uint16_t*)ptr,len-1);
		ptr += 2*len;
	}
	OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_AUTHCHAL,ah,ptr-ah.bs,OBEX_FL_FIT_ONE_PACKET);
	free((void*)ah.bs);
	return 0;
}

ssize_t obex_auth_unpack_response (obex_headerdata_t h,
				   uint32_t size,
				   /* out */ uint8_t digest[16],
				   /* out */ uint8_t nonce[16],
				   /* out */ uint8_t user[21])
{
	int len = 0;
	uint32_t i = 0;
	for (; i < size; i += h.bs[i+1]) {
		uint8_t htype = h.bs[i];
		uint8_t hlen = h.bs[i+1];
		const uint8_t* hdata = h.bs+i+2;

		switch (htype){
		case 0x00: /* digest */
			if (hlen != sizeof(digest))
				return -1;
			memcpy(digest,hdata,sizeof(digest));
			break;

		case 0x01: /* user ID */
			if ((size_t)hlen > sizeof(user))
				return -1;
			len = hlen;
			memcpy(user,hdata,hlen);
			break;

		case 0x02: /* nonce */
			if (hlen != sizeof(nonce))
				return -1;
			memcpy(nonce,hdata,sizeof(nonce));
			break;

		default:
			return -1;
		}
	}
	return len;
}

int obex_auth_check_response (uint8_t digest[16],
			      const uint8_t nonce[16],
 			      const uint8_t* pass,
			      size_t len)
{
	uint8_t d[16];

	memset(d,0,sizeof(d));
	obex_auth_calc_digest(d,nonce,pass,len);
	if (memcmp(d,digest,sizeof(d)) != 0)
		return 0;

	return 1;
}

/* Function for an OBEX client.
 */
int obex_auth_add_response (obex_t* handle,
			    obex_object_t* obj,
			    uint8_t nonce[16],
			    const uint8_t* user,
			    size_t ulen,
			    const uint8_t* pass,
			    size_t plen)
{
	obex_headerdata_t ah;
        uint8_t* ptr;

	ah.bs = malloc(2+16 + 2+ulen + 2+16);
	if (!ah.bs)
		return -ENOMEM;
	ptr = (uint8_t*)ah.bs;

	/* add digest */
	*ptr++ = 0x00;
	*ptr++ = 16;
	obex_auth_calc_digest(ptr,nonce,pass,plen);
	ptr += 16;

	/* add user */
	if (user) {
		*ptr++ = 0x01;
		*ptr++ = ulen;
		memcpy(ptr,user,ulen);
		ptr += ulen;
	}

	/* add nonce */
	*ptr++ = 0x00;
	*ptr++ = 16;
	memcpy(ptr,nonce,16);
	ptr += 16;

	OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_AUTHRESP,ah,ptr-ah.bs,OBEX_FL_FIT_ONE_PACKET);
	free((void*)ah.bs);
	return 0;
}

int obex_auth_unpack_challenge (obex_headerdata_t h,
				uint32_t size,
				/* out */ uint8_t nonce[16],
				/* out */ uint8_t* opts,
				/* out */ uint16_t* realm,
				size_t realm_size)
{
	/* Note: there may be more than one challenge set,
	 *       this will only unpack the first one
	 */
	int len = 0;
	uint32_t i = 0;
	int nonce_count = 0;
	for (; i < size; i += h.bs[i+1]) {
		uint8_t htype = h.bs[i];
		uint8_t hlen = h.bs[i+1];
		const uint8_t* hdata = h.bs+i+2;

		switch (htype){
		case 0x00: /* nonce */
			if (nonce_count)
				return len;
			if (hlen != sizeof(nonce))
				return -1;
			memcpy(nonce,hdata,sizeof(nonce));
			++nonce_count;
			break;

		case 0x01: /* options */
			if (opts) {
				if ((size_t)hlen != 1)
					return -1;
				*opts = *hdata;
			}
			break;

		case 0x02: /* realm */
			if (realm) {
				if (*hdata != 0xFF) /* only support unicode */
					return -1;
				--hlen;
				++hdata;

				if (hdata[hlen] != 0x00 ||
				    hdata[hlen-1] != 0x00)
					realm_size -= 2;
				if (hlen > realm_size)
					return -1;
				memset(realm,0,realm_size);
				memcpy(realm,hdata,hlen);
				ucs2_ntoh(realm,hlen/2);
				len = utf16len(realm);
			}
			break;

		default:
			return -1;
		}
	}
	return len;
}
