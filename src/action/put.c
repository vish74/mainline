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
#include "io.h"
#include "utf.h"
#include "net.h"
#include "action.h"

#include "core.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

static
int put_close (file_data_t* data, bool keep)
{
	return io_close(data->io, &data->transfer, keep);
}

static
int put_open (file_data_t* data)
{
	int err;

	if (io_state(data->io) & IO_STATE_OPEN)
		return 0;

	err = io_open(data->io, &data->transfer, IO_TYPE_PUT);
	if (err)
		return err;

	return 0;
}

static
int put_write (file_data_t* data, const uint8_t* buf, int len)
{
	if (!(io_state(data->io) & IO_STATE_OPEN))
		return -EBADF;

	return io_write(data->io, buf,(size_t)len);
}

static
int put_delete (file_data_t* data)
{
	return io_delete(data->io, &data->transfer);
}

void obex_action_put (file_data_t* data, obex_object_t* obj, int event)
{
	obex_t* handle = data->net_data->obex;
	struct io_transfer_data *transfer = &data->transfer;

	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		(void)OBEX_ObjectReadStream(handle,obj,NULL);
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

	case OBEX_EV_STREAMAVAIL:
		if (!(io_state(data->io) & IO_STATE_OPEN)) {
			if (!obex_object_headers(data, obj))
				data->error = OBEX_RSP_BAD_REQUEST;
		}
		if (!data->error) {
			const uint8_t* buf = NULL;
			int len = OBEX_ObjectReadStream(handle,obj,&buf);

			/* Always create the file even when no data is received */
			if (put_open(data))
				data->error = OBEX_RSP_FORBIDDEN;

			dbg_printf(data, "got %d bytes of streamed data\n", len);
			if (len) {
				if (put_write(data, buf, len))
					data->error = OBEX_RSP_FORBIDDEN;
			}
		}
		obex_send_response(data, obj, data->error);
		break;

	case OBEX_EV_REQ:
		if (data->target == OBEX_TARGET_FTP &&
		    !(io_state(data->io) & IO_STATE_OPEN))
		{
			if (!obex_object_headers(data, obj))
				data->error = OBEX_RSP_BAD_REQUEST;
			else
				(void)put_delete(data);
		}
		obex_send_response(data, obj, data->error);
		break;

	case OBEX_EV_LINKERR:
	case OBEX_EV_PARSEERR:
	case OBEX_EV_ABORT:
		data->error = 0xFF;
		/* no break */
	case OBEX_EV_REQDONE:
		if (io_state(data->io) & IO_STATE_OPEN) {
			(void)put_close(data, (data->error == 0));
		}
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
