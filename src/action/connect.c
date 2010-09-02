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
#include "core.h"

static uint8_t obex_uuid_ftp[] = {
	0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2,
	0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09
};

static struct {
	enum obex_target target;
	const struct obex_target_ops *target_ops;
	enum net_obex_protocol protocol;
	struct {
		size_t size;
		uint8_t *data;
	} uuid;
} obex_target_map[] = {
	{
		.target = OBEX_TARGET_FTP,
		.target_ops = &obex_target_ops_ftp,
		.protocol = NET_OBEX_FTP,
		.uuid =  {
			.size = sizeof(obex_uuid_ftp),
			.data = obex_uuid_ftp,
		},
	}
};
#define TARGET_MAP_COUNT (sizeof(obex_target_map)/sizeof(*obex_target_map))

static int check_target_header(file_data_t* data,
			       obex_headerdata_t value, uint32_t vsize)
{
	for (unsigned int i = 0; i < TARGET_MAP_COUNT; ++i) {
		struct net_data *n = data->net_data;

		if (vsize == obex_target_map[i].uuid.size &&
		    memcmp(value.bs, obex_target_map[i].uuid.data, vsize) == 0 &&
		    (n->enabled_protocols & obex_target_map[i].protocol) != 0)
		{
			data->target = obex_target_map[i].target;
			data->target_ops = obex_target_map[i].target_ops;
			return 1;
		}
	}

	return 0;
}

static int check_headers(file_data_t* data, obex_object_t* obj) {
	obex_t* handle = data->net_data->obex;
	uint8_t id = 0;
	obex_headerdata_t value;
	uint32_t vsize;
	struct io_transfer_data *transfer;
	int target_found = 0;

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
			/* only accept the first target */
			if (!target_found)
				target_found = check_target_header(data, value,
								   vsize);
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

static void add_connection_header(obex_t* handle, obex_object_t* obj,
				  unsigned int id)
{
	obex_headerdata_t hv;

	hv.bq4 = id;
	OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_CONNECTION, hv, 4,
			     OBEX_FL_FIT_ONE_PACKET);
}

static void add_who_header(obex_t* handle, obex_object_t* obj,
			   enum obex_target target)
{
	obex_headerdata_t hv;

	/* add who header with same content as target header from client */
	for (unsigned int i = 0; i < TARGET_MAP_COUNT; ++i) {
		if (target == obex_target_map[i].target) {
			hv.bs = obex_target_map[i].uuid.data;
			OBEX_ObjectAddHeader(handle, obj, OBEX_HDR_WHO, hv,
					     obex_target_map[i].uuid.size,
					     OBEX_FL_FIT_ONE_PACKET);
		}
	}
}

static void connect_request(file_data_t* data, obex_object_t* obj)
{
	obex_t* handle = data->net_data->obex;	
	uint8_t respCode = 0;

	/* Default to ObjectPush */
	data->target = OBEX_TARGET_OPP;
	data->target_ops = &obex_target_ops_opp;

	if (!check_headers(data, obj))
		respCode = OBEX_RSP_BAD_REQUEST;

	else {
		/* we must tell the client that the UUID was recognized */
		if (data->target != OBEX_TARGET_OPP) {
			add_connection_header(handle, obj, data->id);
			add_who_header(handle, obj, data->target);
		}
		if (data->transfer.path) {
			free(data->transfer.path);
			data->transfer.path = NULL;
		}
		respCode = net_security_init(data->net_data, data->auth, obj);
	}

	obex_send_response(data, obj, respCode);
}

const struct obex_target_event_ops obex_action_connect = {
	.request = connect_request,
};
