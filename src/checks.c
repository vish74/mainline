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
#include <stdbool.h>

static
bool name_check_cb(int c) {
	return !(c == (int)':' || c == (int)'\\' || c == (int)'/' || iscntrl(c));
}

static
bool strcheck (const uint8_t *s, bool (*check)(int c)) {
	for (; *s != 0; ++s)
		if (!check((int)*s))
			return false;
	return true;
}

int check_name (const uint8_t *name) {
	return strcheck(name, name_check_cb);
}

int check_type (const char *type) {
	size_t len = strlen(type);
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
