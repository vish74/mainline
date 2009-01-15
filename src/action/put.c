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
int put_close (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);

	return io_close(data);
}

static
int put_wait_for_ok (FILE* f)
{
	char ret[4+1];
	memset(ret, 0, sizeof(ret));
	fgets(ret, sizeof(ret), f);
	if (strncmp(ret, "OK\n", 3) != 0 ||
	    strncmp(ret, "OK\r\n", 4) != 0)
		return -EPERM;
	return 0;
}

static
int put_open (obex_t* handle, const char* script) {
	file_data_t* data = OBEX_GetUserData(handle);
	
	if (script != NULL && strlen(script) > 0) {
		int err = 0;
		const char* args[] = { script, "put", NULL };
		
		err = io_script_open(data, script, (char**)args);
		if (err)
			return err;
		return put_wait_for_ok(data->in);

	} else
		return io_file_open(data, IO_FLAG_WRITE);
}

static
int put_write (obex_t* handle, const uint8_t* buf, int len) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err;

	if (!buf)
		return -EINVAL;
	if (!data->out)
		return -EBADF;
	(void)fwrite(buf,(size_t)len,1,data->out);
	err = ferror(data->out);
	if (err)
		return -err;
	return 0;
}

static
int put_revert (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err = io_close(data);

	if (!err && data->child == (pid_t)-1) {
		uint8_t* n = utf16to8(data->name);		
		if (unlink((char*)n) == -1) /* remove the file */
			err = -errno;
	}

	return err;
}

void obex_action_put (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);

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
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		if (data->type) {
			free(data->type);
			data->type = NULL;
		}
		data->count += 1;
		data->length = 0;
		data->time = 0;
		data->out = NULL;
		break;

	case OBEX_EV_REQCHECK:
		if (data->out == NULL
		    && put_open(handle, get_io_script()) < 0)
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
			if ((data->out == NULL
			     && put_open(handle, get_io_script()) < 0)
			    || put_write(handle,buf,len))
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
		}
		break;
	}

	case OBEX_EV_REQDONE:
		(void)put_close(handle);
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
		break;

	case OBEX_EV_ABORT:
		(void)put_revert(handle);
		break;
	}
}
