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

uint16_t* ucs2dup (const uint16_t* s) {
	size_t len = ucs2len(s) + 2;
	uint16_t *s2;

	if (!s) {
		errno = EINVAL;
		return NULL;
	}
	s2 = malloc(len);
	if (!s2)
		return NULL;
	memset(s2, 0, len);
	memcpy(s2, s, len);
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

size_t utf16count(const uint16_t* s) {
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

static uint16_t* utf16to32 (const uint16_t* in, uint32_t *out)
{
	uint32_t onechar = 0;

	/* surrogates */
	if ((in[0] & 0xD800) == 0xD800)
	{
		if ((in[1] & 0xDC00) == 0xDC00) {
			onechar |= (*(in++) & 0x03FF) << 10;
			onechar |= *(in++) & 0x03FF;
			onechar += 0x10000;
		} else {
			onechar = *(in++);
		}
	} else {
		onechar = *(in++);
	}
	*out = onechar;
	return (uint16_t*)in;
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

static uint16_t* utf32to16 (uint32_t in, uint16_t* out)
{
	if (in <= 0xFFFF) {
		*(out++) = (in & 0xFFFF);
	} else if (in <= 0x10FFFF) {
		in -= 0x10000;
		*(out++) = 0xD800 | ((in >> 10) & 0x3FF);
		*(out++) = 0xDC00 | (in & 0x3FF);
	} else {
		errno = ERANGE;
		out = NULL;
	}

	return out;
}

uint8_t* utf16to8 (const uint16_t* c)
{
	size_t sd = (4 * utf16count(c)) + 1;
	uint8_t *buf;

	if (!c) { 
		errno = EINVAL;
		return NULL;
	}

	buf = malloc(sd);
	if (buf) {
		size_t sc = utf16len(c);
		uint8_t *d = buf;
		const uint16_t *k = c;

		memset(d, 0, sd);
		while (k < c+sc) {
			uint32_t t;

			k = utf16to32(k, &t);
			d = utf32to8(t, d);
		}
	}

	return buf;
}

uint16_t* utf8to16 (const uint8_t* c)
{
	size_t sd = (2 * utf8count(c)) + 2;
	uint16_t *buf;

	if (!c) {
		errno = EINVAL;
		return NULL;
	}

	buf = malloc(sd);
	if (buf) {
		size_t sc = utf8len(c);
		uint16_t *d = buf;
		const uint8_t *k = c;

		memset(d, 0, sd);
		while (k && d && k < c+sc) {
			uint32_t t;
			k = utf8to32(k, &t);
			if (k)
				d = utf32to16(t, d);
		}
	}

	return buf;
}

#ifdef TEST
static int test_utf8 (uint32_t from, uint32_t to) {
	uint32_t i, k;
	uint8_t tmp[6];
	void *status;

	printf("Testing UTF-8...\n");
	for (i = from; i <= to; ++i) {
		printf("\rTest value: 0x%08x", i);
		memset(tmp, 0, sizeof(tmp));
		status = utf32to8(i, tmp);
		if (!status) {
			printf("\nutf32to8() failed");
			break;
		}
		status = utf8to32(tmp, &k);
		if (!status || i != k) {
			printf("\nutf8to32() failed");
			break;
		}
	}
	printf("\n");

	return (i > to);
}

static int test_utf16 (uint32_t from, uint32_t to) {
	uint32_t i, k;
	uint16_t tmp[2];
	void *status;

	printf("Testing UTF-16...\n");
	for (i = from; i <= to; ++i) {
		if (i == 0xD800 && 0xE000 < to)
			i = 0xE000;
		printf("\rTest value: 0x%08x", i);
		memset(tmp, 0, sizeof(tmp));
		status = utf32to16(i, tmp);
		if (!status) {
			printf("\nutf32to16() failed");
			break;
		}
		status = utf16to32(tmp, &k);
		if (!status || i != k) {
			printf("\nutf16to32() failed");
			break;
		}
	}
	printf("\n");

	return (i > to);
}

static int test_string () {
	uint8_t teststr[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	uint16_t *conv1;
	uint8_t *conv2;
	uint16_t *zeroconv1;
	uint8_t *zeroconv2;
	int ret = 0;

	printf("Testing with test string...\n");
	conv1 = utf8to16(teststr);
	conv2 = utf16to8(conv1);
	zeroconv1 = utf8to16(NULL);
	zeroconv2 = utf16to8(NULL);

	if (!conv1)
		ret |= (1 << 0);
	else 
		free(conv1);
	if (strcmp((char*)teststr, (char*)conv2) != 0)
		ret |= (1 << 2);
	if (!conv2)
		ret |= (1 << 1);
	else
		free(conv2);
	if (zeroconv1)
		ret |= (1 << 2);
	if (zeroconv2)
		ret |= (1 << 2);

	return ret;
}

int main () {
	int ret;

	if (!test_utf16(0, 0x10FFFF))
		printf("failed\n");
	else
		printf("passed\n");

	if (!test_utf8(0, 0x10FFFF))
		printf("failed\n");
	else
		printf("passed\n");

	ret = test_string();
	if (ret)
		printf("failed (0x%x)\n", ret);
	else
		printf("passed\n");
	return 0;
}
#endif
