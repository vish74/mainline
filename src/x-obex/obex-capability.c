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
	char* s = NULL;

	if (caps->size_max != ULONG_MAX)
	{
		if (!s)
			s = malloc(strlen(prefix)+5);
		sprintf(s, "%sSize", prefix);
		xml_print(fd, indent, s, "%lu", caps->size_max);
	}

	if (caps->namelen_max != ULONG_MAX)
	{
		if (!s)
			s = malloc(strlen(prefix)+5);
		sprintf(s, "%sNLen", prefix);
		xml_print(fd, indent, s, "%lu", caps->namelen_max);
	}

	if (s)
		free(s);
}

static
void obex_caps_ext (FILE* fd,
		    unsigned int indent,
		    struct obex_caps_ext* caps)
{
	if (!caps->name)
		return;

	xml_open(fd, indent, "Ext");
	xml_print(fd, indent, "XNam", "%s", caps->name);
	for (unsigned int i = 0; i < caps->value_count; ++i)
		xml_print(fd, indent, "XVal", "%s", caps->value[i]);
	xml_close(fd, indent, "Ext");
}

static
void obex_caps_mem (FILE* fd,
		    unsigned int indent,
		    struct obex_caps_mem* caps)
{
	xml_open(fd, indent++, "Memory");
	if (caps->type)
		xml_print(fd, indent, "MemType", "%s", caps->type);
	if (caps->location)
		xml_print(fd, indent, "Location", "%s", caps->location);
	if (caps->free)
		xml_print(fd, indent, "Free", "%lu", caps->free);
	if (caps->used)
		xml_print(fd, indent, "Used", "%lu", caps->used);
	if (caps->flags & OBEX_CAPS_MEM_SHARED)
		xml_print(fd, indent, "Shared", "%u", 1);
	obex_caps_limit(fd, indent, "File", &caps->file);
	obex_caps_limit(fd, indent, "Folder", &caps->folder);
	if (caps->flags & OBEX_CAPS_MEM_CASESENSE)
		xml_print(fd, indent, "CaseSenN", NULL, 0);
	for (unsigned int i = 0; i < caps->ext_count; ++i)
		obex_caps_ext(fd, indent, &caps->ext[i]);
	xml_close(fd, --indent, "Memory");
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
	for (unsigned int i = 0; i < caps->mem_count; ++i)
		obex_caps_mem(fd, 2, &caps->mem[i]);
	for (unsigned int i = 0; i < caps->ext_count; ++i)
		obex_caps_ext(fd, 2, &caps->ext[i]);
	xml_close(fd, 1, "General");
}

static
void obex_caps_object (FILE* fd,
		       unsigned int indent,
		       struct obex_caps_obj* caps)
{
	if (!caps->type && (!caps->name_ext || !*caps->name_ext))
			return;

	xml_open(fd, indent++, "Object");
	if (caps->type)
		xml_print(fd, indent, "Type", "%s", caps->type);
	for (unsigned int i = 0; i < caps->name_ext_count; ++i)
		xml_print(fd, indent, "Name-Ext", "%s", caps->name_ext[i]);
	if (caps->size)
		xml_print(fd, indent, "Size", "%ul", caps->size);
	for (unsigned int i = 0; i < caps->ext_count; ++i)
		obex_caps_ext(fd, 2, &caps->ext[i]);
	xml_close(fd, --indent, "Object");
}

static
void obex_caps_inbox (FILE* fd,
		      struct obex_caps_inbox* caps)
{
	xml_open(fd, 1, "Inbox");
	for (unsigned int i = 0; i < caps->obj_count; ++i)
		obex_caps_object(fd, 2, &caps->obj[i]);
	for (unsigned int i = 0; i < caps->ext_count; ++i)
		obex_caps_ext(fd, 2, &caps->ext[i]);
	xml_close(fd, 1, "Inbox");
}

static
void obex_caps_uuid (FILE* fd,
		     unsigned int indent,
		     struct obex_caps_uuid *caps)
{
	size_t i = 0, k = 0;

	switch (caps->type) {
	case OBEX_CAPS_UUID_ASCII:
		xml_print(fd, indent, "UUID", "%s", (char*)caps->data);
		break;

	case OBEX_CAPS_UUID_BINARY:
		{
			char tmp[37];
			memset(tmp, 0, sizeof(tmp));
			for (; i < sizeof(caps->data); ++i) {
				if (i == 4 || i == 6 || i == 8 || i == 10)
					tmp[(2*i) + k++] = '-';
				snprintf(tmp+(2*i)+k, 3, "%02X", (unsigned int)caps->data[i]);
			}
			xml_print(fd, indent, "UUID", "%s", tmp);
		}
		break;
	}
}

static
void obex_caps_access (FILE* fd,
		       unsigned int indent,
		       struct obex_caps_access* caps)
{
	xml_open(fd, indent++, "Access");
	if (caps->protocol)
		xml_print(fd, indent, "Protocol", "%s", caps->protocol);
	if (caps->endpoint)
		xml_print(fd, indent, "Endpoint", "%s", caps->endpoint);
	if (caps->target)
		xml_print(fd, indent, "Target", "%s", caps->target);
	for (unsigned int i = 0; i < caps->ext_count; ++i)
		obex_caps_ext(fd, 2, &caps->ext[i]);
	xml_close(fd, --indent, "Access");
}

static
void obex_caps_service (FILE* fd,
			struct obex_caps_service* caps)
{
	if (!caps->name && !caps->uuid)
		return;

	xml_open(fd, 1, "Service");
	if (caps->name)
		xml_print(fd, 2, "Name", "%s", caps->name);
	if (caps->uuid)
		obex_caps_uuid(fd, 2, caps->uuid);
	if (caps->version)
		xml_print(fd, 2, "Version", "%s", caps->version);
	for (unsigned int i = 0; i < caps->obj_count; ++i)
		obex_caps_object(fd, 2, &caps->obj[i]);
	for (unsigned int i = 0; i < caps->access_count; ++i)
		obex_caps_access(fd, 2, &caps->access[i]);
	for (unsigned int i = 0; i < caps->ext_count; ++i)
		obex_caps_ext(fd, 2, &caps->ext[i]);
	xml_close(fd, 1, "Service");
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
