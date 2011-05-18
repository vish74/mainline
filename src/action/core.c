#include "action.h"
#include "utf.h"
#include "net.h"
#include "checks.h"
#include "obexpushd.h"

#include "core.h"

#include "time.h"
#include "compiler.h"

static int obex_obj_hdr_name (file_data_t* data,
			      obex_headerdata_t *value, uint32_t vsize)
{
	struct io_transfer_data *transfer = &data->transfer;
	int len = (vsize / 2) + 1;

	if (transfer->name)
		free(transfer->name);
	transfer->name = calloc(len, sizeof(*transfer->name));
	if (!transfer->name)
		return 0;

	memcpy(transfer->name, value->bs, vsize);
	ucs2_ntoh(transfer->name, len);
	if (debug) {
		uint8_t* n = ucs2_to_utf8(transfer->name);
		dbg_printf(data, "name: \"%s\"\n", (char*)n);
		free(n);
	}
	if (!check_wrap_ucs2(transfer->name, check_name)) {
		dbg_printf(data, "CHECK FAILED: %s\n", "Invalid name string");
		return 0;
	}
	return 1;
}

static int obex_obj_hdr_type (file_data_t* data,
			      obex_headerdata_t *value, uint32_t vsize)
{
	struct io_transfer_data *transfer = &data->transfer;
	int len = vsize + 1;

	if (transfer->type)
		free(transfer->type);
	transfer->type = calloc(len, sizeof(*transfer->type));
	if (!transfer->type)
		return 0;

	memcpy(transfer->type, value->bs, vsize);
	dbg_printf(data, "type: \"%s\"\n", transfer->type);
	if (!check_type((uint8_t*)transfer->type)) {
		dbg_printf(data, "CHECK FAILED: %s\n", "Invalid type string");
		return 0;
	}
	return 1;
}

static int obex_obj_hdr_time (file_data_t* data,
			      obex_headerdata_t *value, uint32_t vsize)
{
	/* ISO8601 formatted ASCII string */
	struct io_transfer_data *transfer = &data->transfer;
	struct tm time;
	char* tmp = calloc(vsize + 1, sizeof(*tmp));
	char* ptr;

	if (!tmp)
		return 0;

	memcpy(tmp, value->bs, vsize);
	dbg_printf(data, "time: \"%s\"\n", tmp);
	tzset();
	ptr = strptime(tmp, "%Y%m%dT%H%M%S", &time);
	if (ptr != NULL) {
		time.tm_isdst = -1;
		transfer->time = mktime(&time);
		if (*ptr == 'Z')
			transfer->time -= timezone;
	}
	free(tmp);
	return 1;
}

static int obex_obj_hdr_time2 (file_data_t* data,
			       obex_headerdata_t *value)
{
	struct io_transfer_data *transfer = &data->transfer;

	/* seconds since Januar 1st, 1970 */
	transfer->time = value->bq4;
	if (debug && transfer->time) {
		struct tm t;
		char tmp[17];

		memset(tmp, 0, sizeof(tmp));
		(void)gmtime_r(&transfer->time, &t);
		if (strftime(tmp, sizeof(tmp), "%Y%m%dT%H%M%SZ", &t) != 0) {
			dbg_printf(data, "time: \"%s\"\n", tmp);
		}
	}
	return 1;
}

static int obex_obj_hdr_descr (file_data_t* data,
			       obex_headerdata_t *value, uint32_t vsize)
{
	uint16_t* desc16 = (uint16_t*)value->bs;

	if (desc16[vsize/2] == 0x0000) {
		uint8_t* desc8 = ucs2_to_utf8(desc16);

		dbg_printf(data, "description: \"%s\"\n", (char*)desc8);
		free(desc8);
	}
	return 1;
}

int obex_object_headers (file_data_t* data, obex_object_t* obj) {
	uint8_t id = 0;
	obex_headerdata_t value;
	uint32_t vsize;
	obex_t* handle = data->net_data->obex;
	struct io_transfer_data *transfer;
	int err = 1;

	if (!data)
		return 0;

	transfer = &data->transfer;
	while (OBEX_ObjectGetNextHeader(handle,obj,&id,&value,&vsize)) {
		dbg_printf(data, "Got header 0x%02x with value length %u\n",
			   (unsigned int)id, (unsigned int)vsize);
		if (!vsize)
			continue;
		switch (id) {
		case OBEX_HDR_NAME:
			err = obex_obj_hdr_name(data, &value, vsize);
			break;

		case OBEX_HDR_TYPE:
			err = obex_obj_hdr_type(data, &value, vsize);
			break;

		case OBEX_HDR_LENGTH:
			transfer->length = value.bq4;
			dbg_printf(data, "size: %d bytes\n", value.bq4);
			break;

		case OBEX_HDR_TIME:
			err = obex_obj_hdr_time(data, &value, vsize);
			break;

		case OBEX_HDR_TIME2:
			err = obex_obj_hdr_time2(data, &value);
			break;

		case OBEX_HDR_DESCRIPTION:
			err = obex_obj_hdr_descr(data, &value, vsize);
			break;

		default:
			/* some unexpected header, may be a bug */
			break;
		}
	}
	return 1;
}

static void obex_action (file_data_t *data, obex_object_t *obj,
			 int event, const struct obex_target_event_ops *ops)
{
	if (!ops)
		return;

	switch (event) {
	case OBEX_EV_REQHINT:
		obex_send_response(data, obj, 0);
		if (ops->request_hint)
			ops->request_hint(data, obj);
		break;

	case OBEX_EV_REQCHECK:
		if (ops->request_check)
			ops->request_check(data, obj);
		break;

	case OBEX_EV_REQ:
		if (ops->request)
			ops->request(data, obj);
		break;

	case OBEX_EV_REQDONE:
		if (ops->request_done)
			ops->request_done(data, obj);
		break;

	case OBEX_EV_STREAMAVAIL:
		if (ops->stream_in)
			ops->stream_in(data, obj);
		break;

	case OBEX_EV_STREAMEMPTY:
		if (ops->stream_out)
			ops->stream_out(data, obj);
		break;

	case OBEX_EV_LINKERR:
	case OBEX_EV_PARSEERR:
	case OBEX_EV_ABORT:
		if (ops->error)
			ops->error(data, obj, event);
		break;
	}
}

static void obex_action_send_bad_request (file_data_t *data, obex_object_t *obj)
{
	obex_send_response(data, obj, OBEX_RSP_BAD_REQUEST);
}

static const struct obex_target_event_ops obex_invalid_action = {
	.request_hint = obex_action_send_bad_request,
};

static void obex_action_send_not_impl (file_data_t *data, obex_object_t *obj)
{
	obex_send_response(data, obj, OBEX_RSP_NOT_IMPLEMENTED);
}

static const struct obex_target_event_ops obex_unknown_action = {
	.request_hint = obex_action_send_not_impl,
};

const struct obex_target_ops obex_target_ops_opp = {
	.put = &obex_action_put,
	.get = &obex_action_get,
	.setpath = &obex_invalid_action,
};

const struct obex_target_ops obex_target_ops_ftp = {
	.put = &obex_action_ftp_put,
	.get = &obex_action_get,
	.setpath = &obex_action_setpath,
};

void obex_action_eventcb (obex_t* handle, obex_object_t* obj,
			  int __unused mode, int event,
			  int obex_cmd, int __unused obex_rsp)
{
	file_data_t* data = OBEX_GetUserData(handle);

	/* re-route the abort command */
	if (obex_cmd == OBEX_CMD_ABORT) {
		obex_cmd = data->command;
		event = OBEX_EV_ABORT;
	}

	/* work-around for openobex bug */
	switch (event) {
	case OBEX_EV_REQHINT:
		data->command = obex_cmd;
		break;

	case OBEX_EV_STREAMAVAIL:
	case OBEX_EV_STREAMEMPTY:
	case OBEX_EV_LINKERR:
	case OBEX_EV_PARSEERR:
		obex_cmd = data->command;
		break;
	}

	if (obex_cmd == OBEX_CMD_PUT ||
	    obex_cmd == OBEX_CMD_GET ||
	    obex_cmd == OBEX_CMD_SETPATH)
	{
		if (!net_security_check(data->net_data)) 
			return;
	}

	switch (obex_cmd) {
	case OBEX_CMD_CONNECT:
		if (data->target_ops)
			obex_action(data, obj, event, data->target_ops->pre_disconnect);
		obex_action(data, obj, event, &obex_action_connect);
		if (data->target_ops)
			obex_action(data, obj, event, data->target_ops->post_connect);
		break;

	case OBEX_CMD_PUT:
		if (data->target_ops)
			obex_action(data, obj, event, data->target_ops->put);
		break;

	case OBEX_CMD_GET:
		if (data->target_ops)
			obex_action(data, obj, event, data->target_ops->get);
		break;

	case OBEX_CMD_SETPATH:
		if (data->target_ops)
			obex_action(data, obj, event, data->target_ops->setpath);
		break;

	case OBEX_CMD_DISCONNECT:
		if (data->target_ops)
			obex_action(data, obj, event, data->target_ops->pre_disconnect);
		obex_action(data, obj, event, &obex_action_disconnect);
		break;

	default:
		obex_action(data, obj, event, &obex_unknown_action);
		break;
	}
}
