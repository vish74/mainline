#include <stdbool.h>
#include <inttypes.h>

#ifndef OBEXPUSH_IO_H
#define OBEXPUSH_IO_H

#include "pipe.h"

enum io_type {
	IO_TYPE_PUT,   /* storing data */
	IO_TYPE_GET,   /* retrieving data */
	IO_TYPE_LISTDIR, /* list directory content */
	IO_TYPE_CAPS, /* print capabilities */
};

#define IO_STATE_OPEN (1 << 0)
#define IO_STATE_EOF  (1 << 1)

struct io_transfer_data {
	char *peername;

	uint8_t* name;
	uint8_t* path;
	char* type;
	size_t length;
	time_t time;
};

struct io_handler;
struct io_handler_ops {
	struct io_handler* (*dup)(struct io_handler *self);
	void (*cleanup)(struct io_handler *self);

	int (*open)(struct io_handler *self, struct io_transfer_data *transfer, enum io_type t);
	int (*close)(struct io_handler *self, struct io_transfer_data *transfer, bool keep);
	int (*delete)(struct io_handler *self, struct io_transfer_data *transfer);
	ssize_t (*read)(struct io_handler *self, void *buf, size_t bufsize);
	ssize_t (*write)(struct io_handler *self, const void *buf, size_t len);

	int (*check_dir)(struct io_handler *self, const uint8_t *dir);
	int (*create_dir)(struct io_handler *self, const uint8_t *dir);
};

struct io_handler {
	struct io_handler_ops *ops;
	unsigned long state;
	void *private_data;
};

struct io_handler* io_script_init(const char *script);
struct io_handler* io_file_init(const char *basedir);
struct io_handler* io_dup (struct io_handler *h);
void io_destroy (struct io_handler *h);

unsigned long io_state(struct io_handler *self);
int io_open (struct io_handler *self, struct io_transfer_data *transfer, enum io_type t);
int io_close (struct io_handler *self, struct io_transfer_data *transfer, bool keep);
int io_delete(struct io_handler *self, struct io_transfer_data *transfer);
ssize_t io_readline(struct io_handler *self, void *buf, size_t bufsize);
ssize_t io_read(struct io_handler *self, void *buf, size_t bufsize);
ssize_t io_write(struct io_handler *self, const void *buf, size_t len);
int io_check_dir(struct io_handler *self, const uint8_t *dir);
int io_create_dir(struct io_handler *self, const uint8_t *dir);

#endif /* OBEXPUSH_IO_H */
