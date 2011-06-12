/* Copyright (C) 2009 Hendrik Sattler <post@hendrik-sattler.de>
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
#include "checks.h"
#include "net.h"
#include "core.h"
#include "utf.h"
#include "setpath.h"

#include <errno.h>

int update_path(
	uint8_t **path_ptr,
	const uint8_t *name
)
{
	uint8_t *path = *path_ptr;
	size_t len = utf8len(name);
	int err = 0;

	if (!name) {
		/* do nothing */

	} else if (len == 0) {
		/* name is empty -> go back to root path */
		if (path) {
			free(path);
			path = NULL;
		}

	} else if (strcmp((char*)name, "..") == 0 && path) {
		/* go one level up */
		char* last = strrchr((char*)path, (int)'/');
		if (last)
			*last = '\0';
		else {
			free(path);
			path = NULL;
		}	

	} else {
		/* name is non-empty -> change to directory */
		if (!check_name(name))
			return -EINVAL;

		len += utf8len(path) + 2;
		if (path) {
			uint8_t *newpath = realloc(path, len);
			if (!newpath)
				err = -errno;
			else {
				path = newpath;
				strcat((char*)path, "/");
				strcat((char*)path, (char*)name);
			}
		} else {
			path = (uint8_t*)strdup((const char*)name);
		}
	}

	*path_ptr = path;
	return err;
}

#define OBEX_FLAG_SETPATH_LEVELUP  (1 << 0)
#define OBEX_FLAG_SETPATH_NOCREATE (1 << 1)

static int update_and_check_path(
	struct io_handler *io,
	struct io_transfer_data *transfer,
	const uint16_t *name16,
	uint8_t *flags
)
{
	uint8_t *name = ucs2_to_utf8(name16);
	int create = ((flags[0] & OBEX_FLAG_SETPATH_NOCREATE) == 0);
	int err = 0;
	const uint8_t* level_up = (const uint8_t*)"..";

	if (!name)
		return -errno;

	if ((flags[0] & OBEX_FLAG_SETPATH_LEVELUP) != 0) {
		(void)update_path(&transfer->path, level_up);
	}

	err = update_path(&transfer->path, name);
	if (!err) {
		err = io_check_dir(io, transfer->path);
		if (err == -ENOENT && create)
			err = io_create_dir(io, transfer->path);

		if (err)
			(void)update_path(&transfer->path, level_up);
	}
	return err;
}

static int check_setpath_headers (file_data_t* data, obex_object_t* obj)
{
	uint8_t id = 0;
	obex_headerdata_t value;
	uint32_t vsize;	
	obex_t* handle = data->net_data->obex;
	uint16_t *name = NULL;
	uint8_t *flags = NULL;
	int len;

	if (!data)
		return -EINVAL;

	if (OBEX_ObjectGetNonHdrData(obj, &flags) != 2)
		return -EINVAL;
	if (debug) 
		dbg_printf(data, "setpath flags=0x%02x\n", flags[0]);

	while (OBEX_ObjectGetNextHeader(handle,obj,&id,&value,&vsize)) {
		dbg_printf(data, "Got header 0x%02x with value length %u\n",
			   (unsigned int)id, (unsigned int)vsize);
		switch (id) {
		case OBEX_HDR_NAME:
			if (name)
				free(name);
			len = (vsize / 2) + 1;
			name = calloc(len, sizeof(*name));
			if (!name)
				return -errno;
			memcpy(name, value.bs, vsize);
			ucs2_ntoh(name, len);
			if (debug) {
				uint8_t* n = ucs2_to_utf8(name);
				dbg_printf(data, "name: \"%s\"\n", (char*)n);
				free(n);
			}
			break;

		default:
			break;
		}
	}

	return update_and_check_path(data->io, &data->transfer, name, flags);
}

static void setpath_request(file_data_t* data, obex_object_t* obj)
{
	uint8_t respCode = 0;

	if (check_setpath_headers(data, obj) < 0) {
		respCode = OBEX_RSP_BAD_REQUEST;
	}
	obex_send_response(data, obj, respCode);
}

const struct obex_target_event_ops obex_action_setpath = {
	.request = setpath_request,
};
