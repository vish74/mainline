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
  OBEX_TARGET_OPP = 0, /* ObjectPush */
  OBEX_TARGET_FTP, /* File Browsing Service */

  OBEX_TARGET_MAX_NB
};

struct obex_target_ops;

/* private data for a client connection */
typedef struct {
	unsigned int id;
	unsigned int count;
	uint8_t error;

	uint8_t buffer[1000];
	enum obex_target target;
	const struct obex_target_ops *target_ops;
	int command;

	struct net_data* net_data;
	struct auth_handler *auth;

	struct io_handler *io;
	struct io_transfer_data transfer;
} file_data_t;

struct obex_target_event_ops {
	void (*request_hint)(file_data_t*, obex_object_t*);
	void (*request_check)(file_data_t*, obex_object_t*);
	void (*request)(file_data_t*, obex_object_t*);
	void (*request_done)(file_data_t*, obex_object_t*);

	void (*stream_in)(file_data_t*, obex_object_t*);
	void (*stream_out)(file_data_t*, obex_object_t*);

	void (*error)(file_data_t*, obex_object_t*, int);
};

struct obex_target_ops {
	const struct obex_target_event_ops *post_connect;
	const struct obex_target_event_ops *put;
	const struct obex_target_event_ops *get;
	const struct obex_target_event_ops *setpath;
	const struct obex_target_event_ops *pre_disconnect;
};

void obex_send_response (file_data_t* data, obex_object_t* obj, uint8_t respCode);

extern int debug;
void dbg_printf (file_data_t *data, const char *format, ...) __attribute__((format(printf,2,3)));

#endif
