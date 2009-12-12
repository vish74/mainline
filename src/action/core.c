#define _GNU_SOURCE

#include "action.h"
#include "utf.h"
#include "obexpushd.h"

#include "core.h"

#include "time.h"

int obex_object_headers (obex_t* handle, obex_object_t* obj) {
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
		case OBEX_HDR_NAME:
			if (transfer->name)
				free(transfer->name);
			transfer->name = malloc(vsize+2);
			if (!transfer->name)
				return 0;
			memset(transfer->name,0,vsize+2);
			memcpy(transfer->name,value.bs,vsize);
			ucs2_ntoh(transfer->name,vsize/2);
			if (debug) {
				uint8_t* n = utf16to8(transfer->name);
				dbg_printf(data, "name: \"%s\"\n", (char*)n);
				free(n);
			}
			if (!check_name(transfer->name)) {
				dbg_printf(data, "CHECK FAILED: %s\n", "Invalid name string");
				return 0;
			}
			break;

		case OBEX_HDR_TYPE:
			if (transfer->type)
				free(transfer->type);
			transfer->type = malloc(vsize+1);
			if (!transfer->type)
				return 0;
			memcpy(transfer->type,value.bs,vsize);
			transfer->type[vsize] = '\0';
			dbg_printf(data, "type: \"%s\"\n", transfer->type);
			if (!check_type(transfer->type)) {
				dbg_printf(data, "CHECK FAILED: %s\n", "Invalid type string");
				return 0;
			}
			break;

		case OBEX_HDR_LENGTH:
			transfer->length = value.bq4;
			dbg_printf(data, "size: %d bytes\n", value.bq4);
			break;

		case OBEX_HDR_TIME:
			/* ISO8601 formatted ASCII string */
		        {
				struct tm time;
				char* tmp = malloc(vsize+1);
				if (!tmp)
					return 0;
				memcpy(tmp, value.bs, vsize);
				tmp[vsize] = '\0';
				dbg_printf(data, "time: \"%s\"\n", tmp);
				tzset();
				strptime(tmp, "%Y-%m-%dT%H:%M:%S", &time); /* uses GNU extensions */
				time.tm_isdst = -1;
				transfer->time = mktime(&time);
				if (tmp[17] == 'Z')
					transfer->time -= timezone;
				free(tmp);
				tmp = NULL;
			}
			break;

		case OBEX_HDR_TIME2:
			/* seconds since Januar 1st, 1970 */
			transfer->time = value.bq4;
			if (debug && transfer->time) {
				struct tm t;
				char *tmp = malloc(17);
				(void)gmtime_r(&transfer->time, &t);
				if (tmp) {
					memset(tmp, 0, 17);
					if (strftime(tmp, 17, "%Y%m%dT%H%M%SZ", &t) == 16) {
						dbg_printf(data, "time: \"%s\"\n", tmp);
					}
					free(tmp);
				}
			}
			break;

		case OBEX_HDR_DESCRIPTION:
		        {
				uint16_t* desc16 = (uint16_t*)value.bs;
				if (desc16[vsize/2] == 0x0000) {
					uint8_t* desc8 = utf16to8(desc16);
					dbg_printf(data, "description: \"%s\"\n", (char*)desc8);
					free(desc8);
				}
			}
			break;

		default:
			/* some unexpected header, may be a bug */
			break;
		}
	}
	return 1;
}