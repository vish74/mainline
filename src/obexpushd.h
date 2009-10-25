#ifndef OBEXPUSHD_H
#define OBEXPUSHD_H

#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "io.h"

/* private data for a client connection */
typedef struct {
	unsigned int id;
	unsigned int count;
	uint8_t error;

	uint8_t buffer[1000];

	struct net_data* net_data;
	struct auth_handler *auth;

	struct io_handler *io;
	struct io_transfer_data transfer;
} file_data_t;

int obex_object_headers (obex_t* handle, obex_object_t* obj);
void obex_send_response (obex_t* handle, obex_object_t* obj, uint8_t respCode);
void dbg_printf (file_data_t *data, const char *format, ...) __attribute__((format(printf,2,3)));

int check_name (uint16_t* name);
int check_type (char* type);

#endif
