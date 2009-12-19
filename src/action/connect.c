/* Copyright (C) 2006-2009 Hendrik Sattler <post@hendrik-sattler.de>
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
#include "action.h"


static uint8_t obex_target_map[OBEX_TARGET_MAX_NB-1][16] = {
	{ /* FTP */
		0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2,
		0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09
	}
};


static int check_connect_headers (obex_t* handle, obex_object_t* obj) {
	uint8_t id = 0;
	obex_headerdata_t value;
	uint32_t vsize;
	file_data_t* data = OBEX_GetUserData(handle);
	struct io_transfer_data *transfer;

	if (!data)
		return 0;

	transfer = &data->transfer;
	while (OBEX_ObjectGetNextHeader(handle,obj,&id,&value,&vsize)) {
		dbg_printf(data, "Got header 0x%02x with value length %u\n",
			   (unsigned int)id, (unsigned int)vsize);
		if (!vsize)
			continue;
		switch (id) {
		case OBEX_HDR_DESCRIPTION:
			/* this would be a self-description of the client */
			break;

		case OBEX_HDR_TARGET:
			if (vsize <= sizeof(obex_target_map[0])) {
				enum obex_target t = OBEX_TARGET_FTP;
				for (; t < OBEX_TARGET_MAX_NB; ++t) {
					if (memcmp(value.bs, obex_target_map[t-2], vsize) == 0) {
						data->target = t;
						break;
					}
				}
				if (t == OBEX_TARGET_MAX_NB)
					return 0;
			}
			break;

		case OBEX_HDR_AUTHCHAL:
			/* not implemented: when the client wants the server to authenticate itself */
			break;

		case OBEX_HDR_AUTHRESP:
			data->net_data->auth_success = auth_verify(data->auth,value,vsize);
			break;

		default:
			break;
		}
	}
	return 1;
}

void obex_action_connect (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	uint8_t respCode = OBEX_RSP_SUCCESS;

	switch (event) {
	case OBEX_EV_REQ: /* A new request is coming in */
		/* Connect must not be used twice by the client */
		if (!data || data->target != OBEX_TARGET_NONE) {
			obex_send_response(handle, obj, OBEX_RSP_BAD_REQUEST);
			break;
		}
		/* Default to ObjectPush */
		data->target = OBEX_TARGET_OPP;

		if (!check_connect_headers(handle,obj))
			respCode = OBEX_RSP_BAD_REQUEST;
		else {
			if (data->target == OBEX_TARGET_FTP) {
				obex_headerdata_t hv;

				/* add connection header */
				hv.bq4 = data->id;
				OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_CONNECTION, hv, 4,
						     OBEX_FL_FIT_ONE_PACKET);

				/* add who header with same content as target header from client */
				hv.bs = obex_target_map[data->target-2];
				OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_WHO, hv,
						     sizeof(obex_target_map[data->target-1]),
						     OBEX_FL_FIT_ONE_PACKET);
			}
			if (data->transfer.path) {
				free(data->transfer.path);
				data->transfer.path = NULL;
			}
			respCode = net_security_init(data->net_data, data->auth, obj);
		}
		obex_send_response(handle, obj, respCode);
		break;
	}
}
