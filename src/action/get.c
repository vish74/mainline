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

#include "obexpushd.h"
#include "utf.h"
#include "io.h"
#include "net.h"
#include "action.h"

#include "core.h"

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

static
void add_headers(file_data_t* data, obex_object_t* obj)
{
	obex_t* handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;
	obex_headerdata_t hv;

	if (transfer->name) {
		size_t len = utf16len(transfer->name);
		if (len) {
			void *bs = utf16dup(transfer->name);
			if (bs) {
				size_t size = (len+1)*sizeof(*transfer->name);
				utf16_hton(bs, len);
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

	/* If length exceeds 4GiB-1, a HTTP header is used instead*/
	if (transfer->length <= UINT32_MAX) {
		hv.bq4 = transfer->length;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_LENGTH,
					   hv,sizeof(hv.bq4),0);
	} else {
		char header[16+19+3];
		snprintf(header, sizeof(header), "Content-Length: %zu\r\n", transfer->length);
		hv.bs = (uint8_t*)header;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_HTTP,
					   hv,strlen(header),0);
	}

	if (transfer->time) {
		char bs[17];
		struct tm t;

		memset(bs, 0, sizeof(bs));
		(void)gmtime_r(&transfer->time, &t);
		if (strftime(bs, sizeof(bs), "%Y%m%dT%H%M%SZ", &t) != 0) {
			hv.bs = (uint8_t*)bs;
			(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_TIME,
						   hv,strlen(bs),0);
		}
	}

	hv.bs = NULL;
	(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
				   hv,0,OBEX_FL_STREAM_START);
}

static
int get_check (
	file_data_t *data,
	struct io_transfer_data *transfer
)
{
	/* either type or name must be set */
	if (!transfer->type || strlen(transfer->type) == 0)
		return (utf16len(transfer->name) != 0);

	if (strncmp(transfer->type, "x-obex/", 7) == 0) {
		if (strcmp(transfer->type+7, "folder-listing") == 0) {
			return (data->target == OBEX_TARGET_FTP);

		} else if (strcmp(transfer->type+7, "capability") == 0) {
			return 1;

		} else if (strcmp(transfer->type+7, "object-profile") == 0) {
			return (utf16len(transfer->name) != 0);

		} else {
			/* unknown x-obex type */
			return 0;
		}
	} else {
		/* request generic file objects with a specific type is not allowed */
		return (utf16len(transfer->name) && strlen(transfer->type));
	}
}

static
int get_close (file_data_t* data)
{
	return io_close(data->io, &data->transfer, true);
}

static
int get_open (file_data_t* data) {
	struct io_transfer_data *transfer = &data->transfer;
	int err = 0;
	
	if (transfer->type && strncmp(transfer->type, "x-obex/", 7) == 0) {
		if (strcmp(transfer->type+7, "folder-listing") == 0) {
			err = io_open(data->io, transfer, IO_TYPE_LISTDIR);

		} else if (strcmp(transfer->type+7, "capability") == 0) {
			err = io_open(data->io, transfer, IO_TYPE_CAPS);

		/* } else if (strcmp(transfer->type+7, "object-profile") == 0) { */

		} else {
			/* unknown x-obex type */
			err = -EINVAL;
		}
	} else
		err = io_open(data->io, transfer, IO_TYPE_GET);

	return err;
}

static
int get_read (file_data_t* data, uint8_t* buf, size_t size)
{
	return (int)io_read(data->io, buf, size);
}

void obex_action_get (file_data_t* data, obex_object_t* obj, int event)
{
	obex_t* handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;
	size_t tLen;
	int len = 0;
	int err;

	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		if (transfer->name) {
			free(transfer->name);
			transfer->name = NULL;
		}
		if (transfer->type) {
			free(transfer->type);
			transfer->type = NULL;
		}
		data->count += 1;
		data->error = 0;
		transfer->length = 0;
		transfer->time = 0;
		break;

	case OBEX_EV_REQ:
		if (!obex_object_headers(data, obj))
			data->error = OBEX_RSP_BAD_REQUEST;

		else if (!get_check(data, transfer)) {
			dbg_printf(data, "%s\n", "Forbidden request");
			data->error = OBEX_RSP_FORBIDDEN;

		} else {
			err = get_open(data);
			if (err < 0 || transfer->length == 0) {
				dbg_printf(data, "%s: %s\n", "Running script failed or no output data", strerror(-err));
				data->error = OBEX_RSP_INTERNAL_SERVER_ERROR;
			}
			add_headers(data, obj);
		}
		obex_send_response(data, obj, data->error);
		break;

	case OBEX_EV_STREAMEMPTY:
		if (!data->error) {
			tLen = sizeof(data->buffer);
			if (transfer->length < tLen)
				tLen = transfer->length;
			len = get_read(data, data->buffer, tLen);
			if (len >= 0) {
				obex_headerdata_t hv;
				unsigned int flags = OBEX_FL_STREAM_DATA;
				hv.bs = data->buffer;
				if (len == 0)
					flags = OBEX_FL_STREAM_DATAEND;
				(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_BODY, hv, len, flags);
				transfer->length -= len;
			} else {
				perror("Reading script output failed");
				data->error = OBEX_RSP_INTERNAL_SERVER_ERROR;
			}
		}
		obex_send_response(data, obj, data->error);
		break;

	case OBEX_EV_LINKERR:
	case OBEX_EV_PARSEERR:
	case OBEX_EV_ABORT:
	case OBEX_EV_REQDONE:
		err = get_close(data);
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
		break;
	}
}
