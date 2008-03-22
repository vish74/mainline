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

#include "obex-capability.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define PROGRAM_NAME "obex-capability"
#define PROGRAM_VERSION "0.1"

void print_disclaimer () {
	fprintf(stderr,
		PROGRAM_NAME" "PROGRAM_VERSION " Copyright (C) 2006 Hendrik Sattler\n"
		"This software comes with ABSOLUTELY NO WARRANTY.\n"
		"This is free software, and you are welcome to redistribute it\n"
		"under certain conditions.\n");
}

void print_help () {
	print_disclaimer();
	fprintf(stderr,
		"\n"
		"Usage: %s [<options>]\n", PROGRAM_NAME);
	fprintf(stderr,
		"\n"
		"Options:\n"
		" -V <vendor>  vendor name (default: dummy vendor)\n"
		" -M <model>   model description (default: dummy model)\n"
		" -h           this help message\n");
}

int main (int argc, char** argv)
{
	struct obex_capability caps = {
		.general = {
			.vendor = NULL,
			.model = NULL,
		},
	};

	int err = 0;
	FILE* fd = stdout;
	int c;

	while ((c = getopt(argc,argv,"V:M:h")) != -1) {
		switch (c) {
		case 'V':
			if (optarg)
				caps.general.vendor = optarg;
			break;
		case 'M':
			if (optarg)
				caps.general.model = optarg;
			break;
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		}
	}

	print_disclaimer();
	err = obex_capability(fd,&caps);

	if (err) {
		fprintf(stderr,"%s\n",strerror(-err));
		exit(EXIT_FAILURE);
	} else {
		exit(EXIT_SUCCESS);
	}
}
