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
   
#define _GNU_SOURCE

#include "utf.h"

#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

static
int strcheck (uint8_t* s, int (*check)(int c)) {
	for (; *s != 0; ++s)
		if (check((int)*s))
			return 1;
	return 0;
}

int check_name (uint16_t* name) {
	uint8_t* n = utf16to8(name);
	
	if (strchr((char*)n,(int)':') ||
	    strchr((char*)n,(int)'\\') ||
	    strchr((char*)n,(int)'/') ||
	    strcheck(n,iscntrl)) {
		free(n);
		return 0;
	}
	free(n);
	return 1;
}

int check_type (char* type) {
	size_t len = strlen(type);
	size_t i = 0;
	size_t k = 0;

	for (; i < len; ++i) {
		if (type[i] == '/')
			++k;
		if (!isascii((int)type[i])
		    || isspace((int)type[i])
		    || iscntrl((int)type[i])
		    || k > 1)
			return 0;
	}
	return 1;
}
