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
#include "io.h"
#include "utf.h"
#include "net.h"
#include "action.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

static
int put_close (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);

	return io_close(data->io, &data->transfer, true);
}

static
int put_open (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err;

	if (io_state(data->io) & IO_STATE_OPEN)
		return 0;

	err = io_open(data->io, &data->transfer, IO_TYPE_PUT);
	if (err)
		return err;

	return 0;
}

static
int put_write (obex_t* handle, const uint8_t* buf, int len) {
	file_data_t* data = OBEX_GetUserData(handle);

	if (!(io_state(data->io) & IO_STATE_OPEN)) {
		int err = put_open(handle);
		if(err)
			return err;
	}

	return io_write(data->io, buf,(size_t)len);
}

static
int put_revert (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	return io_close(data->io, &data->transfer, false);
}

void obex_action_put (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	struct io_transfer_data *transfer = &data->transfer;

	if (data->error &&
	    (event == OBEX_EV_REQ ||
	     event == OBEX_EV_REQCHECK ||
	     event == OBEX_EV_STREAMAVAIL))
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
		(void)OBEX_ObjectReadStream(handle,obj,NULL);
		data->error = 0;
		if (transfer->name) {
			free(transfer->name);
			transfer->name = NULL;
		}
		if (transfer->type) {
			free(transfer->type);
			transfer->type = NULL;
		}
		data->count += 1;
		transfer->length = 0;
		transfer->time = 0;
		break;

	case OBEX_EV_REQCHECK:
		if (put_open(handle))
			obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
		else
			obex_send_response(handle, obj, OBEX_RSP_CONTINUE);
		break;

	case OBEX_EV_STREAMAVAIL:
	{
		const uint8_t* buf = NULL;
		int len = OBEX_ObjectReadStream(handle,obj,&buf);

		dbg_printf(data, "got %d bytes of streamed data\n", len);
		if (len) {
			int err = put_write(handle,buf,len);
			if (err)
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
		}
		break;
	}

	case OBEX_EV_REQDONE:
		(void)put_close(handle);
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

	case OBEX_EV_ABORT:
		(void)put_revert(handle);
		break;
	}
}
