/* Copyright (C) 2006  Hendrik Sattler
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

#include "utf.h"
#include <arpa/inet.h>
#include <iconv.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

size_t ucs2len (uint16_t* s) {
	size_t n = 0;
	if (s != 0)
		while (s[n] != 0x0000) ++n;
	return n;
}

void ucs2_ntoh (uint16_t* s, size_t len) {
	size_t i = 0;
	for (; i < len; ++i)
		s[i] = ntohs(s[i]);
}

void ucs2_hton (uint16_t* s, size_t len) {
	size_t i = 0;
	for (; i < len; ++i)
		s[i] = htons(s[i]);
}

size_t utf16count(uint16_t* s) {
	size_t n = 0;
	size_t i = 0;
	if (s != NULL)
		for (; s[i] != 0x0000; ++i) {
			/* surrogates, 0xD8** is the first word
			 * so do not count the second one (0xDC**)
			 */
			if ((s[i] & 0xDC00) != 0xDC00)
				++n;
		}
	return n;
}

size_t utf8count(uint8_t* s) {
	size_t n = 0;
	size_t i = 0;
	if (s != NULL)
		for (; s[i] != 0x00; ++i) {
			if ((s[i] & 0xC0) != 0x80)
				++n;
		}
	return n;
}

static
int utf_convert (void* in, size_t len, const char* fromcode,
		 void* out, size_t size, const char* tocode)
{
	char* in_p = in;
	char* out_p = out;
	size_t status = 0;
	iconv_t cd = iconv_open(tocode,fromcode);
	if (cd == (iconv_t)-1)
		return -errno;
	status = iconv(cd,&in_p,&len,&out_p,&size);
	if (status == (size_t)-1)
		return -errno;
	if (iconv_close(cd))
		return -errno;
	return 0;
}

uint8_t* utf16to8 (uint16_t* c)
{
	size_t sc = utf16len(c);
	size_t sd = 4*utf16count(c)+1;
	uint8_t* d = malloc(sd);
	int status;
	
	if (!d)
		return NULL;
	memset(d,0,sd);
	status = utf_convert(c,2*sc,"UTF-16",d,sd,"UTF-8");
	if (status) {
		fprintf(stderr,"UTF conversion failure: %s\n",strerror(-status));
		free(d);
		return NULL;
	}
	return d;
}

uint16_t* utf8to16 (uint8_t* c)
{
	size_t sc = utf8len(c);
	size_t sd = 4*utf8count(c)+2;
	uint16_t* d = malloc(sd);
	int status;
	
	if (!d)
		return NULL;
	status = utf_convert(c,sc,"UTF-8",d,sd,"UTF-16");
	if (status) {
		fprintf(stderr,"UTF conversion failure: %s\n",strerror(-status));
		free(d);
		return NULL;
	}
	return d;
}
