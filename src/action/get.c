/* Copyright (C) 2006-2007 Hendrik Sattler <post@hendrik-sattler.de>
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

#include "obexpushd.h"
#include "utf.h"
#include "io.h"
#include "net.h"
#include "action.h"
#include "core.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>

#define EOL(n) ((n) == '\n' || (n) == '\r')

static
int get_parse_headers (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	char buffer[512+1];

	while (1) {
		size_t len = 0;
		if (fgets(buffer,sizeof(buffer),data->out) == NULL) {
			if (!feof(data->out))
				return -ferror(data->out);
			else
				return -EINVAL;
		}
		len = strlen(buffer);

		if (!EOL(buffer[len-1]) && feof(data->out))
			return -EINVAL;
		
		if (buffer[len-1] == '\n')
			--len;
		if (buffer[len-1] == '\r')
			--len;
		buffer[len] = 0;

		/* stop on the first empty line */
		if (len == 0)
			break;

		/* compare the first part of buffer with known headers
		 * and ignore unknown ones
		 */
		if (strncasecmp(buffer,"Name: ",6) == 0) {
			uint16_t* name = utf8to16((uint8_t*)(buffer+6));
			if (!check_name(name)) {
				free(name);
				return -EINVAL;
			}
			if (data->name)
				free(data->name);
			data->name = name;

		} else if (strncasecmp(buffer,"Length: ",8) == 0) {
			char* endptr;
			long dlen = strtol(buffer+8, &endptr, 10);
			if ((dlen == LONG_MIN || dlen == LONG_MAX) && errno == ERANGE)
				return -errno;

			if (endptr != 0 && (0 <= dlen && dlen <= UINT32_MAX)) {
				data->length = (uint32_t)dlen;
				continue;
			}

		} else if (strncasecmp(buffer,"Type: ",6) == 0) {
			char* type = buffer+6;
			if (!check_type(type))
				return -EINVAL;
			if (data->type)
				free(data->type);
			data->type = strdup(type);
		} else
			continue;
	}
	return 0;
}

static
int get_close (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);

	return io_close(data);
}

static
int get_open (obex_t* handle, const char* script) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err = 0;
	const char* args[] = { script, "get", NULL };

	err = io_script_open(data, script, (char**)args);
	if (err == 0)
		err = get_parse_headers(handle);

	return err;
}

static
int get_read (obex_t* handle, uint8_t* buf, size_t size) {
	file_data_t* data = OBEX_GetUserData(handle);
	size_t status;

	if (!data->out)
		return -EBADF;
	status = fread(buf, sizeof(*buf), size, data->out);
	
	if (status < size && !feof(data->out))		
		return -ferror(data->out);
	else
		return status;
}

void obex_action_get (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	int len = 0;

	if (data->error &&
	    (event == OBEX_EV_REQ ||
	     event == OBEX_EV_REQCHECK ||
	     event == OBEX_EV_STREAMEMPTY))
	{
		obex_send_response(handle, obj, data->error);
		return;
	}
	if (!obex_object_headers(handle,obj)) {
		obex_send_response(handle, obj, OBEX_RSP_BAD_REQUEST);
		return;
	}
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		data->error = 0;
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		/* in case that there is no TYPE header */
		data->type = strdup("text/x-vcard");
		data->count += 1;
		data->length = 0;
		data->time = 0;
		if (!get_io_script()) {
			/* There is no default object to get */
			fprintf(stderr, "No script defined\n");
			obex_send_response(handle, obj, OBEX_RSP_NOT_FOUND);
			break;
		}
		break;

	case OBEX_EV_REQ:
	{
		obex_headerdata_t hv;
		
		if (data->out == NULL) {
			/* If there is a default object but the name header
			 * is non-empty. Special case is that
			 * type == x-obex/object-profile, then name contains the
			 * real type
			 */
			/* TODO: allowing x-obex/folder-listing would essentially implement
			 * obexftp. However, this requires the FBS-UUID and secure directory
			 * traversal. That's not implemented, yet.
			 */
			if ((strcmp(data->type,"x-obex/object-profile") != 0 && data->name)
			    || strcmp(data->type,"x-obex/folder-listing") == 0)
			{
				printf("%u.%u: %s\n", data->id, data->count,
				       "Forbidden request");
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
				break;
			}

			if (get_open(handle, get_io_script()) < 0 ||
			    data->length == 0)
			{
				data->out = NULL;
				printf("%u.%u: %s\n", data->id, data->count,
				       "Running script failed or no output data");
				obex_send_response(handle, obj, OBEX_RSP_INTERNAL_SERVER_ERROR);
				break;
			}
			if (event == OBEX_EV_REQCHECK)
				break;
		}

		obex_send_response(handle, obj, OBEX_RSP_CONTINUE);
		if (data->name) {
			size_t size = utf16len(data->name);
			if (size) {
				size += 2;
				hv.bs = malloc(size);
				if (hv.bs) {
					memcpy((char*)hv.bs,data->name,size);
					ucs2_hton((uint16_t*)hv.bs,size);
					(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_NAME,
								   hv,size,0);
					free((uint8_t*)hv.bs);
				}
			}
		}
		hv.bs = (const uint8_t*)data->type;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_TYPE,
					   hv,strlen((char*)hv.bs),0);
		hv.bq4 = data->length;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_LENGTH,
					   hv,sizeof(hv.bq4),0);
		hv.bs = NULL;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
					   hv,0,
					   OBEX_FL_STREAM_START);
	}
		break;

	case OBEX_EV_STREAMEMPTY:
		len = get_read(handle,data->buffer,sizeof(data->buffer));
		if (len >= 0) {
			obex_headerdata_t hv;
			hv.bs = data->buffer;
			if (len == sizeof(data->buffer))
				(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
							   hv,len,
							   OBEX_FL_STREAM_DATA);
			else
				(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
							   hv,len,
							   OBEX_FL_STREAM_DATAEND);			
		} else {
			perror("Reading script output failed");
			obex_send_response(handle, obj, OBEX_RSP_INTERNAL_SERVER_ERROR);
		}
		break;

	case OBEX_EV_LINKERR:
	case OBEX_EV_PARSEERR:
	case OBEX_EV_ABORT:
	case OBEX_EV_REQDONE:
	{
		int err = get_close(handle);
		if (err)
			fprintf(stderr, "%s\n", strerror(-err));
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		if (data->type) {
			free(data->type);
			data->type = NULL;
		}
		data->length = 0;
		data->time = 0;
	}
		break;
	}
}
