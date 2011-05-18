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
#include <errno.h>
#include <string.h>
#include <stdio.h>

size_t ucs2len (const uint16_t* s) {
	size_t n = 0;
	if (s != 0)
		while (s[n] != 0x0000) ++n;
	return n;
}

size_t utf8len (const uint8_t* s) {
	if (s)
		return strlen((char*)(s));
	return 0;
}

uint16_t* ucs2dup (const uint16_t* s) {
	size_t len = ucs2len(s) + 1;
	uint16_t *s2;

	if (!s) {
		errno = EINVAL;
		return NULL;
	}
	s2 = calloc(len, sizeof(*s));
	if (!s2)
		return NULL;
	memcpy(s2, s, len*sizeof(*s));
	return s2;
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

size_t ucs2count(const uint16_t* s) {
	return ucs2len(s);
}

size_t utf8count(const uint8_t* s) {
	size_t n = 0;
	size_t i = 0;
	if (s != NULL)
		for (; s[i] != 0x00; ++i) {
			if ((s[i] & 0xC0) != 0x80)
				++n;
		}
	return n;
}

#if defined(HAVE_ICONV)
#include <iconv.h>
static int utf_convert (const void* in, size_t len, const char* fromcode,
			void* out, size_t size, const char* tocode)
{
	char* in_p = (char*)in;
	char* out_p = out;
	size_t status = 0;
	iconv_t cd = iconv_open(tocode,fromcode);

	if (cd == (iconv_t)-1)
		return -errno;

	status = iconv(cd, &in_p, &len, &out_p, &size);
	if (status == (size_t)-1)
		return -errno;

	if (iconv_close(cd))
		return -errno;

	return 0;
}

#else // HAVE_ICONV
static uint8_t* utf8to32 (const uint8_t* in, uint32_t *out)
{
	uint32_t onechar = 0;

	if ((in[0] & 0x80) == 0x00) {
		onechar = *(in++);

	} else {
		const uint8_t prefix[6] = { 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
		const uint8_t mask[6] = { 0x80, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };
		size_t count = 0;

		do {
			++count;
		} while ((in[count] & 0xC0) == 0x80 && count <= 6);

		/* check the maximum number of bytes that can be
		 * converted to 32bit integer.
		 * check the first character to validate count value.
		 */
		if (count > 6 ||
		    (in[0] & mask[count - 1]) != prefix[count - 1]) {
			errno = EILSEQ;
			return NULL;
		}

		onechar = *(in++) ^ prefix[count - 1];
		while (--count) {
			onechar <<= 6;
			onechar |= *(in++) & 0x3F;
		}
	}

	*out = onechar;
	return (uint8_t*)in;
}

static uint8_t* utf32to8 (uint32_t in, uint8_t* out)
{
	if (in <= 0x7F) {
		*(out++) = (in & 0x7F);
	} else {
		struct {
			uint32_t max_value;
			uint8_t mask;
		} unicode[6] = {
			{ 0x0000007F, 0x00 },
			{ 0x000007FF, 0xC0 },
			{ 0x0000FFFF, 0xE0 },
			{ 0x001FFFFF, 0xF0 },
			{ 0x03FFFFFF, 0xF8 },
			{ 0x7FFFFFFF, 0xFC }
		};
		unsigned int i = 0, k = 1;
		for (; i < 6; ++i) {
			if (in <= unicode[i].max_value) {
				break;
			}
		}
		if (i >= 6) {
			errno = ERANGE;
			return NULL;
		}

		*(out++) = unicode[i].mask | ((in >> (i * 6)) & (unicode[i].max_value >> (i * 6)));
		for (; k <= i; ++k) {
			*(out++) = 0x80 | ((in >> ((i - k) * 6)) & 0x3F);
		}
	}

	return out;
}
#endif // HAVE_ICONV

uint8_t* ucs2_to_utf8 (const uint16_t* c)
{
	uint8_t *buf;
	size_t buflen;
	size_t count;

	if (!c) {
		errno = EINVAL;
		return NULL;
	}

	count = ucs2len(c);
	buflen = (3 * count) + 1;
	buf = calloc(buflen, sizeof(*buf));
	if (buf) {
#if defined(HAVE_ICONV)
		int status = utf_convert(c, 2 * count, "UCS-2",
					 buf, buflen, "UTF-8");
		if (status) {
			errno = -status;
			free(buf);
			return NULL;
		}

#else // HAVE_ICONV
		uint8_t *d = buf;

		for (size_t i = 0; i < count; ++i) {
			/* UCS-2 directly maps to UTF-32 codepoints... */
			uint32_t t = (uint32_t)c[i];

			/* ...and then we can use the normal conversion */
			d = utf32to8(t, d);
		}
#endif // HAVE_ICONV
	}
	return buf;
}

uint16_t* utf8_to_ucs2 (const uint8_t* c)
{
	uint16_t *buf;
	size_t buflen;

	if (!c) {
		errno = EINVAL;
		return NULL;
	}

	buflen = utf8count(c) + 2;
	buf = calloc(buflen, sizeof(*buf));
	buflen *= sizeof(*buf);
	if (buf) {
		size_t count = utf8len(c);
#if defined(HAVE_ICONV)
		int status = utf_convert(c, count, "UTF-8",
					 buf, buflen, "UCS-2");
		if (status) {
			errno = -status;
			free(buf);
			return NULL;
		}

#else // HAVE_ICONV
		uint16_t *d = buf;
		const uint8_t *k = c;

		while (k && d && k < c+count) {
			uint32_t t;
			k = utf8to32(k, &t);

			if (t <= 0xFFFF)
				*d = (uint16_t)(t & 0xFFFF);
			else
				*d = 0xFFFD; /* Unicode replacement character */
		}
#endif // HAVE_ICONV
	}

	return buf;
}
