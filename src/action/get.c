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

#include "compiler.h"

static void add_name_header(file_data_t *data, obex_object_t *obj)
{
	obex_t *handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;
	size_t len = utf16len(transfer->name);

	if (len) {
		void *bs = utf16dup(transfer->name);

		if (bs) {
			size_t size = (len+1)*sizeof(*transfer->name);
			obex_headerdata_t hv;

			utf16_hton(bs, len);
			hv.bs = bs;
			(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_NAME,
						   hv, size, 0);
			hv.bs = NULL;
			free(bs);
		}
	}
}

static void add_type_header(file_data_t *data, obex_object_t *obj)
{
	obex_t *handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;
	obex_headerdata_t hv;

	hv.bs = (uint8_t *)transfer->type;
	(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_TYPE,
				   hv, strlen((char*)hv.bs), 0);
}

static void add_length_header(file_data_t *data, obex_object_t *obj)
{
	obex_t *handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;
	obex_headerdata_t hv;

	/* If length exceeds 4GiB-1, a HTTP header is used instead*/
	if (transfer->length <= UINT32_MAX) {
		hv.bq4 = transfer->length;
		(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_LENGTH,
					   hv, sizeof(hv.bq4), 0);

	} else {
		char header[16+19+3];

		snprintf(header, sizeof(header), "Content-Length: %zu\r\n",
			 transfer->length);
		hv.bs = (uint8_t*)header;
		(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_HTTP,
					   hv, strlen(header), 0);
	}

}

static void add_time_header(file_data_t *data, obex_object_t *obj)
{
	obex_t *handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;
	obex_headerdata_t hv;
	char bs[17];
	struct tm t;

	memset(bs, 0, sizeof(bs));
	(void)gmtime_r(&transfer->time, &t);
	if (strftime(bs, sizeof(bs), "%Y%m%dT%H%M%SZ", &t) != 0) {
		hv.bs = (uint8_t*)bs;
		(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_TIME,
					   hv, strlen(bs), 0);
	}
}

static void add_data_header(file_data_t *data, obex_object_t *obj)
{
	obex_t *handle = data->net_data->obex;
	obex_headerdata_t hv;

	hv.bs = NULL;
	(void)OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_BODY,
				   hv, 0, OBEX_FL_STREAM_START);
}

static void add_headers(file_data_t *data, obex_object_t *obj)
{
	struct io_transfer_data *transfer = &data->transfer;

	if (transfer->name) {
		add_name_header(data, obj);
	}

	if (transfer->type) {
		add_type_header(data, obj);
	}

	add_length_header(data, obj);

	if (transfer->time) {
		add_time_header(data, obj);
	}

	add_data_header(data, obj);
}

static int get_check(struct io_transfer_data *transfer, enum obex_target target)
{
	/* either type or name must be set */
	if (!transfer->type || strlen(transfer->type) == 0)
		return (utf16len(transfer->name) != 0);

	if (strncmp(transfer->type, "x-obex/", 7) == 0) {
		if (strcmp(transfer->type+7, "folder-listing") == 0) {
			return (target == OBEX_TARGET_FTP);

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

static int get_open (file_data_t* data)
{
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

static void get_reqhint(file_data_t *data, obex_object_t __unused *obj)
{
	/* A new request is coming in */
	struct io_transfer_data *transfer = &data->transfer;

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
}

static void get_request(file_data_t *data, obex_object_t *obj)
{
	struct io_transfer_data *transfer = &data->transfer;

	if (!obex_object_headers(data, obj))
		data->error = OBEX_RSP_BAD_REQUEST;

	else if (!get_check(transfer, data->target)) {
		dbg_printf(data, "%s\n", "Forbidden request");
		data->error = OBEX_RSP_FORBIDDEN;

	} else {
		int err = get_open(data);

		if (err < 0 || transfer->length == 0) {
			dbg_printf(data, "%s: %s\n", "Running script failed or no output data", strerror(-err));
			data->error = OBEX_RSP_INTERNAL_SERVER_ERROR;
		}
		add_headers(data, obj);
	}
	obex_send_response(data, obj, data->error);
}

static void get_stream_out(file_data_t *data, obex_object_t *obj)
{
	struct io_transfer_data *transfer = &data->transfer;

	if (!data->error) {
		size_t tLen = sizeof(data->buffer);
		int len;

		if (transfer->length < tLen)
			tLen = transfer->length;

		len = (int)io_read(data->io, data->buffer, tLen);
		if (len >= 0) {
			obex_headerdata_t hv;
			unsigned int flags = OBEX_FL_STREAM_DATA;
			obex_t* handle = data->net_data->obex;

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
}

static void get_done(file_data_t *data, obex_object_t __unused *obj)
{
	struct io_transfer_data *transfer = &data->transfer;
	int err = io_close(data->io, &data->transfer, true);;

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

static void get_abort(file_data_t *data, obex_object_t __unused *obj,
		      int __unused event)
{
	get_done(data, obj);
}

const struct obex_target_event_ops obex_action_get = {
	.request_hint = get_reqhint,
	.request = get_request,
	.request_done = get_done,

	.stream_out = get_stream_out,

	.error = get_abort,
};
