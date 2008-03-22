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

#include "obex-folder-listing.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <locale.h>
#include <string.h>

#define PROGRAM_NAME "obex-folder-listing"
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
		" -P  show parent folder indicator\n"
		" -H  also list hidden files/directories\n"
		" -t  show time attributes\n"
		" -p  show permission attributes\n"
		" -o  show file owner attribute\n"
		" -g  show file group attribute\n"
		" -h  this help message\n");
}

int main (int argc, char** argv)
{
	char* name = ".";
	FILE* fd = stdout;
	int err;
	int c;
	int flags = 0;

	while ((c = getopt(argc,argv,"PHtpogh")) != -1) {
		switch (c) {
		case 'P':
			flags |= OFL_FLAG_PARENT;
			break;
		case 'H':
			flags |= OFL_FLAG_HIDDEN;
			break;
		case 't':
			flags |= OFL_FLAG_TIMES;
			break;
		case 'p':
			flags |= OFL_FLAG_PERMS;
			break;
		case 'o':
			flags |= OFL_FLAG_OWNER;
			break;
		case 'g':
			flags |= OFL_FLAG_GROUP;
			break;
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		}
	}

	if (optind < argc)
		name = argv[optind];

	print_disclaimer();
	
	setlocale(LC_ALL, "");
	err = obex_folder_listing(fd, name, flags);

	if (err) {
		fprintf(stderr,"%s\n",strerror(-err));
		exit(EXIT_FAILURE);
	} else {
		exit(EXIT_SUCCESS);
	}
}
