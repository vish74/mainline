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
#include "xml_simple.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#if defined(APP)
#define PROGRAM_NAME "obex-capability"
#define PROGRAM_VERSION "0.1"
#endif

static
void obex_caps_general (FILE* fd, struct obex_caps_general* caps)
{
	if (caps) {
		xml_open(fd,1,"General");
		xml_print(fd,2,"Manufacturer","%s",
			  (caps->vendor? caps->vendor: "dummy vendor"));
		xml_print(fd,2,"Model","%s",
			  (caps->model? caps->model: "dummy model"));
		xml_close(fd,1,"General");
	}
}

int obex_capability (FILE* fd, struct obex_capability* caps)
{
	int err = 0;
	fprintf(fd,
		"<?xml version=\"1.0\"?>\n"
		"<!DOCTYPE folder-listing SYSTEM \"obex-capability.dtd\">\n");
	xml_open(fd,0,"Capability Version=\"1.0\"");
	obex_caps_general(fd,&caps->general);
	xml_close(fd,0,"Capability");
	return err;
}

#if defined(APP)
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
#endif