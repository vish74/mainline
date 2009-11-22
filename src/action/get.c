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
#include "core.h"
#include "action.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#define EOL(n) ((n) == '\n' || (n) == '\r')

static
int parse_script_headers (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	struct io_transfer_data *transfer = &data->transfer;
	char buffer[512+1];

	while (1) {
		size_t len = 0;
		int err = io_readline(data->io, buffer, sizeof(buffer));
		if (err < 0) {
			return err;
		} else if (err == 0) {
			return -EINVAL;
		}
		len = strlen(buffer);

		if (len == 0 || !EOL(buffer[len-1]))
			return -EINVAL;
		
		if (len && buffer[len-1] == '\n')
			--len;
		if (len && buffer[len-1] == '\r')
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
			if (transfer->name)
				free(transfer->name);
			transfer->name = name;

		} else if (strncasecmp(buffer,"Length: ",8) == 0) {
			char* endptr;
			long dlen = strtol(buffer+8, &endptr, 10);
			if ((dlen == LONG_MIN || dlen == LONG_MAX) && errno == ERANGE)
				return -errno;

			if (endptr != 0 && (0 <= dlen && dlen <= UINT32_MAX)) {
				transfer->length = (uint32_t)dlen;
				continue;
			}

		} else if (strncasecmp(buffer,"Type: ",6) == 0) {
			char* type = buffer+6;
			if (!check_type(type))
				return -EINVAL;
			if (transfer->type)
				free(transfer->type);
			transfer->type = strdup(type);

		} else if (strncasecmp(buffer, "Time: ", 6) == 0) {
			char* timestr = buffer+6;
			struct tm time;

			tzset();
			/* uses GNU extensions */
			strptime(timestr, "%Y-%m-%dT%H:%M:%S", &time);
			time.tm_isdst = -1;
			transfer->time = mktime(&time);
			if (strlen(timestr) > 17 && timestr[17] == 'Z')
				transfer->time -= timezone;

		} else
			continue;
	}
	return 0;
}

static
void add_headers(obex_t* handle, obex_object_t* obj) {
	file_data_t* data = OBEX_GetUserData(handle);
	struct io_transfer_data *transfer = &data->transfer;
	obex_headerdata_t hv;

	if (transfer->name) {
		size_t size = utf16len(transfer->name);
		if (size) {
			void *bs;
			size += 2;
			bs = malloc(size);
			if (bs) {
				memcpy(bs, transfer->name, size);
				ucs2_hton(bs, size);
				hv.bs = bs;
				(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_NAME,
							   hv,size,0);
				hv.bs = NULL;
				free(bs);
			}
		}
	}

	if (transfer->type) {
		hv.bs = (uint8_t *)transfer->type;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_TYPE,
					   hv,strlen((char*)hv.bs),0);
	}

	hv.bq4 = transfer->length;
	(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_LENGTH,
				   hv,sizeof(hv.bq4),0);
	if (transfer->time) {
		void *bs = malloc(17);
		if (bs) {
			struct tm t;
			(void)gmtime_r(&transfer->time, &t);
			memset(bs, 0, 17);
			if (strftime(bs, 17, "%Y%m%dT%H%M%SZ", &t) == 16) {
				hv.bs = bs;
				(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_TIME,
							   hv,strlen(bs),0);
				hv.bs = NULL;
			}
			free(bs);
		}
	}

	hv.bs = NULL;
	(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
				   hv,0,OBEX_FL_STREAM_START);
}

static
int get_close (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);

	return io_close(data->io, &data->transfer, true);
}

static
int get_open (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	struct io_transfer_data *transfer = &data->transfer;
	int err = 0;
	
	if (strncmp(transfer->type, "x-obex/", 7) == 0)
		err = io_open(data->io, transfer, IO_TYPE_XOBEX);
	else
		err = io_open(data->io, transfer, IO_TYPE_GET);
	if (err == 0)
		err = parse_script_headers(handle);

	return err;
}

static
int get_read (obex_t* handle, uint8_t* buf, size_t size) {
	file_data_t* data = OBEX_GetUserData(handle);

	return (int)io_read(data->io, buf, size);
}

void obex_action_get (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	struct io_transfer_data *transfer = &data->transfer;
	int len = 0;
	int err;

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
		if (transfer->name) {
			free(transfer->name);
			transfer->name = NULL;
		}
		/* in case that there is no TYPE header */
		transfer->type = strdup("text/x-vcard");
		data->count += 1;
		transfer->length = 0;
		transfer->time = 0;
		break;

	case OBEX_EV_REQCHECK:
	case OBEX_EV_REQ:
		if (strncmp(transfer->type, "x-obex/", 7) == 0) {
			/* Also, allowing x-obex/folder-listing would essentially implement
			 * file browsing service. However, this requires the FBS-UUID and
			 * secure directory traversal. That's not implemented, yet.
			 */

			if (strcmp(transfer->type+7,"folder-listing") == 0) {
				dbg_printf(data, "%s\n", "Forbidden request");
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
				break;
			}

		} else {
			/* A non-x-obex type was specified but also a name was given, thus
			 * requesting not only a default object. This is not allowed.
			 */
			if (transfer->name) {
				dbg_printf(data, "%s\n", "Forbidden request");
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
				break;
			}
		}

		err = get_open(handle);
		if (err < 0 || transfer->length == 0) {
			dbg_printf(data, "%s: %s\n", "Running script failed or no output data", strerror(-err));
			obex_send_response(handle, obj, OBEX_RSP_INTERNAL_SERVER_ERROR);
			break;
		}

		if (event == OBEX_EV_REQCHECK)
			break;

		obex_send_response(handle, obj, OBEX_RSP_CONTINUE);
		add_headers(handle, obj);
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
			dbg_printf(data, "%s\n", strerror(-err));
		if (transfer->name) {
			free(transfer->name);
			transfer->name = NULL;
		}
		if (transfer->type) {
			free(transfer->type);
			transfer->type = NULL;
		}
		transfer->length = 0;
		transfer->time = 0;
	}
		break;
	}
}
