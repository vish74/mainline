#ifndef OBEXPUSHD_H
#define OBEXPUSHD_H

#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "io.h"

enum obex_target {
  OBEX_TARGET_NONE = 0, /* NOT CONNECTED */
  OBEX_TARGET_OPP, /* ObjectPush */
  OBEX_TARGET_FTP, /* File Browsing Service */

  OBEX_TARGET_MAX_NB
};

/* private data for a client connection */
typedef struct {
	unsigned int id;
	unsigned int count;
	uint8_t error;

	uint8_t buffer[1000];
	enum obex_target target;

	struct net_data* net_data;
	struct auth_handler *auth;

	struct io_handler *io;
	struct io_transfer_data transfer;
} file_data_t;

void obex_send_response (obex_t* handle, obex_object_t* obj, uint8_t respCode);

extern int debug;
void dbg_printf (file_data_t *data, const char *format, ...) __attribute__((format(printf,2,3)));

int check_name (uint8_t *name);
int check_type (uint8_t *type);
int check_wrap_utf16 (uint16_t *name, int (*func)(uint8_t*));

#endif
