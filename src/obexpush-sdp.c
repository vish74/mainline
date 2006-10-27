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

static const char* SDP_SERVICE_NAME = "OBEX Object Push";
static const char* SDP_SERVICE_PROVIDER = "obexpushd";
static const char* SDP_SERVICE_DESCR = "dummy description";

int bt_sdp_session_close (sdp_session_t* session) {
  return sdp_close(session);
}

sdp_session_t* bt_sdp_session_open (uint8_t channel) {
  sdp_session_t* session;

  uuid_t uuid_srv;
  uuid_t uuid_group;
  uuid_t uuid_l2cap;
  uuid_t uuid_rfcomm;
  uuid_t uuid_obex;

  sdp_profile_desc_t desc_srv;
  sdp_data_t* chan;

  sdp_list_t* list_class = NULL;
  sdp_list_t* list_srv = NULL;
  sdp_list_t* list_group = NULL;
  sdp_list_t* list_l2cap = NULL;
  sdp_list_t* list_rfcomm = NULL;
  sdp_list_t* list_obex = NULL;

  uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF };
  uint8_t fdtd = SDP_UINT8;
  void* dtds[sizeof(formats)];
  void* values[sizeof(formats)];
  sdp_data_t* list_formats = NULL;
  size_t i;

  sdp_list_t* list_proto = NULL;
  sdp_list_t* list_access = NULL;
  sdp_record_t* rec = sdp_record_alloc();
  int status;

  /* Service: OBEX-Push */
  list_class = sdp_list_append(list_class,sdp_uuid16_create(&uuid_srv,OBEX_OBJPUSH_SVCLASS_ID));
  sdp_set_service_classes(rec,list_class);

  /* the service is publicly browsable */
  list_group = sdp_list_append(list_group,sdp_uuid16_create(&uuid_group,PUBLIC_BROWSE_GROUP));
  sdp_set_browse_groups(rec,list_group);

  /* protocol descriptor list */
  list_l2cap = sdp_list_append(list_l2cap,sdp_uuid16_create(&uuid_l2cap,L2CAP_UUID));
  list_rfcomm = sdp_list_append(list_rfcomm,sdp_uuid16_create(&uuid_rfcomm,RFCOMM_UUID));
  list_obex = sdp_list_append(list_obex,sdp_uuid16_create(&uuid_obex,OBEX_UUID));

  chan = sdp_data_alloc(SDP_UINT8,&channel);
  list_rfcomm = sdp_list_append(list_rfcomm,chan);

  list_proto = sdp_list_append(list_proto,list_l2cap);
  list_proto = sdp_list_append(list_proto,list_rfcomm);
  list_proto = sdp_list_append(list_proto,list_obex);

  list_access = sdp_list_append(list_access,list_proto);
  sdp_set_access_protos(rec,list_access);

  desc_srv.version = 0x0100;
  list_srv = sdp_list_append(list_srv,sdp_uuid16_create(&desc_srv.uuid, OBEX_OBJPUSH_PROFILE_ID));
  sdp_set_profile_descs(rec,list_srv);

  for (i = 0; i < sizeof(formats); ++i) {
    dtds[i] = &fdtd;
    values[i] = formats+i;
  }
  list_formats = sdp_seq_alloc(dtds,values,sizeof(formats));
  sdp_attr_add(rec,SDP_ATTR_SUPPORTED_FORMATS_LIST,list_formats);

  sdp_set_info_attr(rec,SDP_SERVICE_NAME,SDP_SERVICE_PROVIDER,SDP_SERVICE_DESCR);

  session = sdp_connect(BDADDR_ANY,BDADDR_LOCAL,SDP_RETRY_IF_BUSY);
  status = sdp_record_register(session,rec,0);
  if (status < 0) {
    bt_sdp_session_close(session);
    session = NULL;
  }

  sdp_data_free(chan);
  sdp_list_free(list_class,0);
  sdp_list_free(list_srv,0);
  sdp_list_free(list_group,0);
  sdp_list_free(list_l2cap,0);
  sdp_list_free(list_rfcomm,0);
  sdp_list_free(list_obex,0);
  sdp_data_free(list_formats);
  sdp_list_free(list_proto,0);
  sdp_list_free(list_access,0);
/*   sdp_record_free(rec); */

  return session;
}
