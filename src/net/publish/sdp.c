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

#include "sdp.h"
#include <stdlib.h>

struct obex_sdp_data {
	uuid_t uuid_group;
	sdp_list_t* list_group;

	uuid_t uuid_l2cap;
	sdp_list_t* list_l2cap;

	uuid_t uuid_rfcomm;
	sdp_list_t* list_rfcomm;
	sdp_data_t* chan;

	uuid_t uuid_obex;
	sdp_list_t* list_obex;

	sdp_list_t* list_proto;
	sdp_list_t* list_access;
};

static
int bt_sdp_fill_l2cap (struct obex_sdp_data *data)
{
	data->list_l2cap = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_l2cap, L2CAP_UUID));
	if (!data->list_l2cap)
		return 0;

	data->list_proto = sdp_list_append(NULL, data->list_l2cap);
	if (!data->list_proto)
		return 0;

	return 1;
}

static
int bt_sdp_fill_rfcomm (struct obex_sdp_data *data, uint8_t channel)
{
	data->chan = sdp_data_alloc(SDP_UINT8, &channel);
	if (!data->chan)
		return 0;

	data->list_rfcomm = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_rfcomm, RFCOMM_UUID));
	if (!data->list_rfcomm)
		return 0;

	data->list_rfcomm = sdp_list_append(data->list_rfcomm, data->chan);
	if (!data->list_rfcomm)
		return 0;

	data->list_proto = sdp_list_append(data->list_proto, data->list_rfcomm);
	if (!data->list_proto)
		return 0;

	return 1;
}

static
int bt_sdp_fill_obex (struct obex_sdp_data *data, uint8_t channel)
{
	data->list_group = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_group, PUBLIC_BROWSE_GROUP));
	data->list_obex = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_obex, OBEX_UUID));
	if (!data->list_group || !data->list_obex)
		return 0;

	if (!bt_sdp_fill_l2cap(data))
		return 0;

	if (!bt_sdp_fill_rfcomm(data, channel))
		return 0;

	data->list_proto = sdp_list_append(data->list_proto, data->list_obex);
	if (!data->list_proto)
		return 0;

	data->list_access = sdp_list_append(NULL, data->list_proto);
	if (!data->list_access)
		return 0;

	return 1;
}

static
void bt_sdp_cleanup_obex(struct obex_sdp_data *data)
{
	if (data->list_group) {
		sdp_list_free(data->list_group, 0);
		data->list_group = NULL;
	}
	if (data->list_l2cap) {
		sdp_list_free(data->list_l2cap, 0);
		data->list_l2cap = NULL;
	}
	if (data->list_rfcomm) {
		sdp_list_free(data->list_rfcomm, 0);
		data->list_rfcomm = NULL;
	}
	if (data->list_obex) {
		sdp_list_free(data->list_obex, 0);
		data->list_obex = NULL;
	}
	if (data->list_proto) {
		sdp_list_free(data->list_proto, 0);
		data->list_proto = NULL;
	}
	if (data->list_access) {
		sdp_list_free(data->list_access, 0);
		data->list_access = NULL;
	}
	if (data->chan) {
		sdp_data_free(data->chan);
		data->chan = NULL;
	}
}


static const char* SDP_SERVICE_PROVIDER = "obexpushd";
static const char* SDP_SERVICE_DESCR = "a free OBEX server";
static uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF };
static uint8_t fdtd = SDP_UINT8;

struct obex_opp_sdp_data {
	struct obex_sdp_data obex;

	uuid_t uuid_class;
	sdp_list_t* list_class;

	sdp_profile_desc_t desc_srv;
	sdp_list_t* list_srv;

	void* dtds[sizeof(formats)];
	void* values[sizeof(formats)];
	sdp_data_t* list_formats;
};

static
int bt_sdp_fill_opp (struct obex_opp_sdp_data *data, uint8_t channel, sdp_record_t* rec)
{
	if (!bt_sdp_fill_obex(&data->obex, channel))
		return 0;

	sdp_set_browse_groups(rec, data->obex.list_group);
	sdp_set_access_protos(rec, data->obex.list_access);

	data->list_class = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_class, OBEX_OBJPUSH_SVCLASS_ID));
	if (!data->list_class)
		return 0;
	sdp_set_service_classes(rec, data->list_class);

	sdp_uuid16_create(&data->desc_srv.uuid, OBEX_OBJPUSH_PROFILE_ID);
	data->desc_srv.version = 0x0100;
	data->list_srv = sdp_list_append(NULL, &data->desc_srv);
	if (!data->list_srv)
		return 0;
	sdp_set_profile_descs(rec, data->list_srv);

	for (size_t i = 0; i < sizeof(formats); ++i) {
		data->dtds[i] = &fdtd;
		data->values[i] = formats+i;
	}
	data->list_formats = sdp_seq_alloc(data->dtds, data->values, sizeof(formats));
	if (!data->list_formats)
		return 0;
	sdp_attr_add(rec, SDP_ATTR_SUPPORTED_FORMATS_LIST, data->list_formats);

	sdp_set_info_attr(rec, "OBEX Object Push", SDP_SERVICE_PROVIDER, SDP_SERVICE_DESCR);

	return 1;
}

static
void bt_sdp_cleanup_opp (struct obex_opp_sdp_data *data)
{
	if (data->list_class) {
		sdp_list_free(data->list_class, 0);
		data->list_class = NULL;
	}
	if (data->list_srv) {
		sdp_list_free(data->list_srv, 0);
		data->list_srv = NULL;
	}
	//data->list_formats?
	bt_sdp_cleanup_obex(&data->obex);
}

struct obex_ftp_sdp_data {
	struct obex_sdp_data obex;

	uuid_t uuid_class;
	sdp_list_t* list_class;

	sdp_profile_desc_t desc_srv;
	sdp_list_t* list_srv;

};

static
int bt_sdp_fill_ftp (struct obex_ftp_sdp_data *data, uint8_t channel, sdp_record_t* rec)
{
	if (!bt_sdp_fill_obex(&data->obex, channel))
		return 0;

	sdp_set_browse_groups(rec, data->obex.list_group);
	sdp_set_access_protos(rec, data->obex.list_access);

	data->list_class = sdp_list_append(NULL, sdp_uuid16_create(&data->uuid_class, OBEX_FILETRANS_SVCLASS_ID));
	if (!data->list_class)
		return 0;
	sdp_set_service_classes(rec, data->list_class);

	sdp_uuid16_create(&data->desc_srv.uuid, OBEX_FILETRANS_PROFILE_ID);
	data->desc_srv.version = 0x0100;
	data->list_srv = sdp_list_append(NULL, &data->desc_srv);
	if (!data->list_srv)
		return 0;
	sdp_set_profile_descs(rec, data->list_srv);

	sdp_set_info_attr(rec, "OBEX File Transfer", SDP_SERVICE_PROVIDER, SDP_SERVICE_DESCR);

	return 1;
}

static
void bt_sdp_cleanup_ftp (struct obex_ftp_sdp_data *data)
{
	if (data->list_class) {
		sdp_list_free(data->list_class, 0);
		data->list_class = NULL;
	}
	if (data->list_srv) {
		sdp_list_free(data->list_srv, 0);
		data->list_srv = NULL;
	}
	bt_sdp_cleanup_obex(&data->obex);
}

#define SDP_DATA_REC_COUNT 2
struct sdp_data {
	sdp_session_t* session;
	struct {
		sdp_record_t* handle;
		union {
			struct obex_opp_sdp_data opp;
			struct obex_ftp_sdp_data ftp;
		} prot;
	} rec[SDP_DATA_REC_COUNT];
};

static
struct sdp_data* bt_sdp (bdaddr_t* device, uint8_t channel, unsigned long protocols)
{
	struct sdp_data* data = malloc(sizeof(*data));
	if (!data)
		return NULL;

	memset(data, 0, sizeof(*data));
	data->session = sdp_connect(device, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
	if (!data->session) {
		free(data);
		return NULL;
	}

	if ((protocols & BT_SDP_PROT_OBEX_PUSH) != 0) {
		data->rec[0].handle = sdp_record_alloc();
		if (!data->rec[0].handle || !bt_sdp_fill_opp(&data->rec[0].prot.opp, channel, data->rec[0].handle)) {
			perror("Setting up OPP SDP entry failed");
			bt_sdp_cleanup_opp(&data->rec[0].prot.opp);
			return NULL;
		}
	}

	if ((protocols & BT_SDP_PROT_OBEX_FTP) != 0) {
		data->rec[1].handle = sdp_record_alloc();
		if (!data->rec[1].handle || !bt_sdp_fill_ftp(&data->rec[1].prot.ftp, channel, data->rec[1].handle)) {
			perror("Setting up FTP SDP entry failed");
			if ((protocols & BT_SDP_PROT_OBEX_PUSH) != 0)
				bt_sdp_cleanup_opp(&data->rec[0].prot.opp);
			bt_sdp_cleanup_ftp(&data->rec[1].prot.ftp);
			return NULL;
		}
	}

	return data;
}

void* bt_sdp_session_open (
	bdaddr_t* device,
	uint8_t channel,
	unsigned long protocols
)
{
	int status = 0;
	struct sdp_data* data = bt_sdp(device, channel, protocols);

	if (!data)
		return NULL;

	for (int i = 0; i < SDP_DATA_REC_COUNT && status >= 0; ++i) {
		if (data->rec[i].handle == NULL)
			continue;
		status = sdp_device_record_register(data->session, device,
						    data->rec[i].handle, 0);
	}
	if (status < 0) {
		bt_sdp_session_close(data, device);
		data = NULL;
	}

	return data;
}

void bt_sdp_session_close (
	void* session_data,
	bdaddr_t* device
)
{
	struct sdp_data* data = session_data;

	if (data->session == NULL)
		return;

	for (int i = 0; i < SDP_DATA_REC_COUNT; ++i) {
		if (data->rec[i].handle == NULL)
			continue;
		(void)sdp_device_record_unregister(data->session, device,
						   data->rec[i].handle);
		data->rec[i].handle = NULL;
		if (i == 0)
			bt_sdp_cleanup_opp(&data->rec[0].prot.opp);
		else if (i == 1)
			bt_sdp_cleanup_ftp(&data->rec[1].prot.ftp);
	}
	sdp_close(data->session);
	data->session = NULL;
	free(data);
}
