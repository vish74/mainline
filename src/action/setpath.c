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
#include "net.h"
#include "core.h"
#include "utf.h"

#include <errno.h>

#define OBEX_FLAG_SETPATH_LEVELUP  (1 << 0)
#define OBEX_FLAG_SETPATH_NOCREATE (1 << 1)

static int update_path(
	struct io_handler *io,
	struct io_transfer_data *transfer,
	const uint16_t *name,
	uint8_t *flags
)
{
	size_t len = utf16len(name);
	int err = 0;

	if ((flags[0] & OBEX_FLAG_SETPATH_LEVELUP) && transfer->path) {
		/* go one level up */
		char* last = strrchr(transfer->path, (int)'/');
		if (last)
			*last = '\0';
		else {
			free(transfer->path);
			transfer->path = NULL;
		}	
	}

	if (!name) {
		/* do nothing */

	} else if (len == 0) {
		/* name is empty -> go back to root path */
		if (transfer->path) {
			free(transfer->path);
			transfer->path = NULL;
		}		

	} else {
		/* name is non-empty -> change to directory */
		uint8_t *n = utf16to8(name);

		if (!n)
			return -errno;

		if (!check_name(n))
			return -EINVAL;

		if (strcmp((char*)n, "..") == 0)
			return -EINVAL;

		len = utf8len((uint8_t*)transfer->path) + 1 + utf8len(n) + 1;
		if (transfer->path) {
			char *newpath = realloc(transfer->path, len);
			if (!newpath)
				err = -errno;
			else {
				transfer->path = newpath;
				strcat(transfer->path, "/");
				strcat(transfer->path, (char*)n);
			}
			free(n);
		} else {
			transfer->path = (char*)n;
		}
		n = NULL;
		if (!err) {
			err = io_check_dir(io, transfer->path);
			if (err == -ENOENT && !(flags[0] & OBEX_FLAG_SETPATH_NOCREATE)) {
				err = io_create_dir(io, transfer->path);
			}
			if (err) {
				char* last = strrchr(transfer->path, (int)'/');
				if (last)
					*last = '\0';
				else {
					free(transfer->path);
					transfer->path = NULL;
				}
			}
		}
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
			name = malloc(vsize+2);
			if (!name)
				return -errno;
			memset(name,0,vsize+2);
			memcpy(name,value.bs,vsize);
			ucs2_ntoh(name,vsize/2);
			if (debug) {
				uint8_t* n = utf16to8(name);
				dbg_printf(data, "name: \"%s\"\n", (char*)n);
				free(n);
			}
			break;

		default:
			break;
		}
	}

	return update_path(data->io, &data->transfer, name, flags);
}

void obex_action_setpath (file_data_t* data, obex_object_t* obj, int event)
{
	uint8_t respCode = OBEX_RSP_SUCCESS;

	switch (event) {
	case OBEX_EV_REQ:
		if (check_setpath_headers(data, obj) < 0) {
			respCode = OBEX_RSP_BAD_REQUEST;
		}
		obex_send_response(data, obj, respCode);
		break;
	}
}
