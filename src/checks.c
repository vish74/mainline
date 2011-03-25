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
   
#include "utf.h"
#include "checks.h"

#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

static
int name_check_cb(int c) {
	return !(c == (int)':' || c == (int)'\\' || c == (int)'/' || iscntrl(c));
}

static
int strcheck (uint8_t *s, int (*check)(int c)) {
	for (; *s != 0; ++s)
		if (check((int)*s))
			return 1;
	return 0;
}

int check_name (uint8_t *name) {
	return strcheck(name, name_check_cb);
}

int check_type (uint8_t *type) {
	size_t len = strlen((char*)type);
	size_t i = 0;

	for (; i < len; ++i) {
		if (type[i] == '/')
			break;
		if (!isascii((int)type[i]) ||
		    !(isalpha((int)type[i]) || type[i] == '-' || type[i] == '.')) /* "x-", "vnd.", "prs." */
			return 0;
	}
	if (++i >= len)
		return 0;
	for (; i < len; ++i) {
		if (!isascii((int)type[i]) || !isprint((int)type[i]))
			return 0;
	}
	return 1;
}

int check_wrap_ucs2 (uint16_t *name, int (*func)(uint8_t*)) {
	uint8_t* n = ucs2_to_utf8(name);
	int result = func(n);
	free(n);
	return result;
}
