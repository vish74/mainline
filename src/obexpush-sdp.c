/* Copyright (C) 2006 Hendrik Sattler <post@hendrik-sattler.de>
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

#include "obexpush-sdp.h"
#include <stdlib.h>

static const char* SDP_SERVICE_NAME = "OBEX Object Push";
static const char* SDP_SERVICE_PROVIDER = "obexpushd";
static const char* SDP_SERVICE_DESCR = "dummy description";
static uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF };
static uint8_t fdtd = SDP_UINT8;

struct obexpush_sdp_data {
	sdp_session_t* session;
	sdp_record_t* rec;

	uuid_t uuid_srv;
	uuid_t uuid_group;
	uuid_t uuid_l2cap;
	uuid_t uuid_rfcomm;
	uuid_t uuid_obex;

	sdp_data_t* chan;
	sdp_data_t* list_formats;

	sdp_list_t* list_class;
	sdp_list_t* list_srv;
	sdp_list_t* list_group;
	sdp_list_t* list_l2cap;
	sdp_list_t* list_rfcomm;
	sdp_list_t* list_obex;
	sdp_list_t* list_proto;
	sdp_list_t* list_access;

	void* dtds[sizeof(formats)];
	void* values[sizeof(formats)];
	sdp_profile_desc_t desc_srv;
};

static
struct obexpush_sdp_data* bt_sdp_obexpush (
	bdaddr_t* device,
	uint8_t channel
)
{
	size_t i;
	int status;

	struct obexpush_sdp_data* data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	memset(data, 0, sizeof(*data));

	for (i = 0; i < sizeof(formats); ++i) {
		data->dtds[i] = &fdtd;
		data->values[i] = formats+i;
	}
	data->desc_srv.version = 0x0100;

	data->session = sdp_connect(device, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
	if (!data->session)
		return NULL;

	data->rec = sdp_record_alloc();
	data->chan = sdp_data_alloc(SDP_UINT8, &channel);
	data->list_formats = sdp_seq_alloc(data->dtds, data->values, sizeof(formats));

	data->list_class  = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_srv, OBEX_OBJPUSH_SVCLASS_ID));
	data->list_group  = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_group, PUBLIC_BROWSE_GROUP));
	data->list_l2cap  = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_l2cap, L2CAP_UUID));
	data->list_rfcomm = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_rfcomm, RFCOMM_UUID));
	data->list_rfcomm = sdp_list_append(data->list_rfcomm, data->chan);
	data->list_obex   = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_obex, OBEX_UUID));

	data->list_proto  = sdp_list_append(NULL, data->list_l2cap);
	data->list_proto  = sdp_list_append(data->list_proto, data->list_rfcomm);
	data->list_proto  = sdp_list_append(data->list_proto, data->list_obex);
	data->list_access = sdp_list_append(NULL, data->list_proto);
	data->list_srv    = sdp_list_append(NULL, sdp_uuid16_create(&data->desc_srv.uuid, OBEX_OBJPUSH_PROFILE_ID));

	sdp_set_service_classes(data->rec, data->list_class);
	sdp_set_browse_groups(data->rec, data->list_group);
	sdp_set_access_protos(data->rec, data->list_access);
	sdp_set_profile_descs(data->rec, data->list_srv);
	sdp_attr_add(data->rec, SDP_ATTR_SUPPORTED_FORMATS_LIST, data->list_formats);
	sdp_set_info_attr(data->rec, SDP_SERVICE_NAME, SDP_SERVICE_PROVIDER, SDP_SERVICE_DESCR);

	return data;
}

void* bt_sdp_session_open (
	bdaddr_t* device,
	uint8_t channel
)
{
	int status;
	struct obexpush_sdp_data* data = bt_sdp_obexpush(device, channel);
	if (!data)
		return NULL;

	status = sdp_device_record_register(data->session, device, data->rec, 0);
	if (status < 0)
		sdp_close(data->session);

	return data;
}

void bt_sdp_session_close (
	void* session_data,
	bdaddr_t* device
)
{
	struct obexpush_sdp_data* data = session_data;
	(void)sdp_device_record_unregister(data->session, device, data->rec);
	sdp_close(data->session);

	sdp_list_free(data->list_class, 0);
	sdp_list_free(data->list_srv, 0);
	sdp_list_free(data->list_group, 0);
	sdp_list_free(data->list_l2cap, 0);
	sdp_list_free(data->list_rfcomm, 0);
	sdp_list_free(data->list_obex, 0);
	sdp_list_free(data->list_proto, 0);
	sdp_list_free(data->list_access, 0);
	sdp_data_free(data->chan);
	free(data);
}
