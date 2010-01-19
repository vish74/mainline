#include <sys/types.h>
#include <stdbool.h>
#include <inttypes.h>

#ifndef OBEXPUSH_IO_H
#define OBEXPUSH_IO_H

int pipe_open (const char* command, char** args, int client_fds[2], pid_t *pid);
void pipe_close (int client_fds[2]);

enum io_type {
	IO_TYPE_PUT,   /* storing data */
	IO_TYPE_GET,   /* retrieving data */
	IO_TYPE_CREATEDIR,   /* create a directory */
	IO_TYPE_XOBEX, /* x-obex services */
};

#define IO_STATE_OPEN (1 << 0)
#define IO_STATE_EOF  (1 << 1)

struct io_transfer_data {
	char *peername;

	uint16_t* name;
	char* path;
	char* type;
	size_t length;
	time_t time;
};

struct io_handler;
struct io_handler_ops {
	int (*open)(struct io_handler *self, struct io_transfer_data *transfer, enum io_type t);
	int (*close)(struct io_handler *self, struct io_transfer_data *transfer, bool keep);
	struct io_handler* (*copy)(struct io_handler *self);
	void (*cleanup)(struct io_handler *self);
	ssize_t (*read)(struct io_handler *self, void *buf, size_t bufsize);
	ssize_t (*write)(struct io_handler *self, const void *buf, size_t len);
	int (*check_dir)(struct io_handler *self, const char *dir);
	int (*create_dir)(struct io_handler *self, const char *dir);
};

struct io_handler {
	struct io_handler_ops *ops;
	unsigned long state;
	void *private_data;
};

struct io_handler* io_script_init(const char *script);
struct io_handler* io_file_init(const char *basedir);
struct io_handler* io_copy (struct io_handler *h);
void io_destroy (struct io_handler *h);

unsigned long io_state(struct io_handler *self);
int io_open (struct io_handler *self, struct io_transfer_data *transfer, enum io_type t);
int io_close (struct io_handler *self, struct io_transfer_data *transfer, bool keep);
ssize_t io_readline(struct io_handler *self, void *buf, size_t bufsize);
ssize_t io_read(struct io_handler *self, void *buf, size_t bufsize);
ssize_t io_write(struct io_handler *self, const void *buf, size_t len);
int io_check_dir(struct io_handler *self, const char *dir);
int io_create_dir(struct io_handler *self, const char *dir);

#endif /* OBEXPUSH_IO_H */
