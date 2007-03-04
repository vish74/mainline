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
void obex_caps_version (FILE* fd,
			unsigned int indent,
			const char* name,
			struct obex_caps_version* caps)
{
	if (caps->version) {
		if (caps->date) {
			xml_el_open(fd, indent, name, 1,
				    " version=\"%s\" date=\"%s\"",
				    caps->version, caps->date);
		} else {
			xml_el_open(fd, indent, name, 1,
				    " version=\"%s\"", caps->version);
		}
	} else {
		if (caps->date) {
			xml_el_open(fd, indent, name, 1,
				    " date=\"%s\"", caps->date);
		} else {
			xml_el_open(fd, indent, name, 1, NULL, 0);
		}
	}
}

static
void obex_caps_limit (FILE* fd,
		      unsigned int indent,
		      char* prefix,
		      struct obex_caps_limit* caps)
{
	char* s = malloc(strlen(prefix)+5);

	sprintf(s, "%sSize", prefix);
	xml_open(fd, indent, s);
	fprintf(fd, "%lu", caps->size_max);
	xml_close(fd,indent,s);

	sprintf(s, "%sNLen", prefix);
	xml_open(fd, indent, s);
	fprintf(fd, "%lu", caps->namelen_max);
	xml_close(fd,indent,s);

	free(s);
}

static
void obex_caps_ext (FILE* fd,
		    unsigned int indent,
		    struct obex_caps_ext* caps)
{
	unsigned int i;
	for (; caps != NULL; ++caps) {
		xml_open(fd, indent, "Ext");
		xml_print(fd, indent, "XNam", "%s", caps->name);
		for (i = 0; caps->value[i] != NULL; ++i)
			xml_print(fd, indent, "XVal", "%s", *caps->value);
		xml_close(fd, indent, "Ext");
	}
}

static
void obex_caps_mem (FILE* fd,
		    unsigned int indent,
		    struct obex_caps_mem* caps)
{
	for (; caps != NULL; ++caps) {
		xml_open(fd, indent, "Memory");
		++indent;
		if (caps->type)
			xml_print(fd, indent, "MemType", "%s", caps->type);
		if (caps->location)
			xml_print(fd, indent, "Location", "%s", caps->location);
		if (caps->free)
			xml_print(fd, indent, "Free", "%u", caps->free);
		if (caps->used)
			xml_print(fd, indent, "Used", "%u", caps->used);
		if (caps->flags & OBEX_CAPS_MEM_SHARED)
			xml_print(fd, indent, "Shared", NULL, 0);
		if (caps->file)
			obex_caps_limit(fd, indent, "File", caps->file);
		if (caps->folder)
			obex_caps_limit(fd, indent, "Folder", caps->folder);
		if (caps->flags & OBEX_CAPS_MEM_CASESENSE)
			xml_print(fd, indent, "CaseSenN", NULL, 0);
		if (caps->ext)
			obex_caps_ext(fd, indent, *caps->ext);
		--indent;
		xml_close(fd, indent, "Memory");
	}
}

static
void obex_caps_general (FILE* fd,
			struct obex_caps_general* caps)
{
	xml_open(fd, 1, "General");
	xml_print(fd, 2, "Manufacturer", "%s",
		  (caps->vendor? caps->vendor: "dummy vendor"));
	xml_print(fd, 2, "Model", "%s",
		  (caps->model? caps->model: "dummy model"));
	if (caps->serial)
		xml_print(fd, 2, "SN", "%s", caps->serial);
	if (caps->oem)
		xml_print(fd, 2, "OEM", "%s", caps->oem);
	if (caps->sw)
		obex_caps_version(fd, 2, "SW", caps->sw);
	if (caps->fw)
		obex_caps_version(fd, 2, "FW", caps->fw);
	if (caps->hw)
		obex_caps_version(fd, 2, "HW", caps->hw);
	if (strlen(caps->lang))
		xml_print(fd, 2, "Language", "%s", caps->lang);
	if (caps->mem)
		obex_caps_mem(fd, 2, *caps->mem);
	if (caps->ext)
		obex_caps_ext(fd, 2, *caps->ext);
	xml_close(fd, 1, "General");
}

static
void obex_caps_inbox (FILE* fd,
		      struct obex_caps_inbox* caps)
{
	fprintf(stderr,"%s elements not supported, yet.","Inbox");
}

static
void obex_caps_service (FILE* fd,
			struct obex_caps_service* caps)
{
	fprintf(stderr,"%s elements not supported, yet.","Service");
}

int obex_capability (FILE* fd, struct obex_capability* caps)
{
	int err = 0;
	fprintf(fd,
		"<?xml version=\"1.0\"");
	if (caps->charset)
		fprintf(fd, "charset=\"%s\"", caps->charset);
	fprintf(fd,
		"?>\n"
		"<!DOCTYPE folder-listing SYSTEM \"obex-capability.dtd\">\n");
	xml_open(fd,0,"Capability Version=\"1.0\"");
	obex_caps_general(fd,&caps->general);
	if (caps->inbox)
		obex_caps_inbox(fd, caps->inbox);
	if (caps->service)
		obex_caps_service(fd, caps->service);
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
