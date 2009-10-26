/* Copyright (C) 2006-2007 Hendrik Sattler <post@hendrik-sattler.de>
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

#define _POSIX_SOURCE

#include "obexpushd.h"

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <utime.h>

#include "io.h"
#include "utf.h"
#include "net.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct io_file_data {
	FILE *in;
	FILE *out;
};

static int io_file_close (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	bool keep
)
{
	struct io_file_data *data = self->private_data;

	if (data->in) {
		if (fclose(data->in) == EOF)
			return -errno;
		data->in = NULL;
	}

	if (data->out) {
		char* name = (char*)utf16to8(transfer->name);

		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;

		if (!keep) {
			if (!name)
				return -ENOMEM;
			if (unlink(name) == -1) /* remove the file */
				return -errno;
			
		} else if (transfer->time) {
			if (name) {
				struct utimbuf times;

				times.actime = transfer->time;
				times.modtime = transfer->time;
				/* setting the time is non-critical */
				(void)utime(name, &times);
			}
		}
		if (name)
			free(name);
	}
	self->state = 0;

	return 0;
}

static int io_file_open (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	enum io_type t
)
{
	int err;
	uint8_t* name = utf16to8(transfer->name);
	struct io_file_data *data = self->private_data;

	if (!name)
		return -EINVAL;

	err = io_file_close(self, transfer, true);
	if (err)
		return err;

	switch (t) {
	case IO_TYPE_PUT:
		fprintf(stderr, "Creating file \"%s\"\n", (char*)name);
		err = open((char*)name, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,
			      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		if (err == -1) {
			fprintf(stderr, "Error: cannot create file: %s\n", strerror(-err));
			goto io_file_error;
		}
#if ! O_CLOEXEC
		(void)fcntl(err, F_SETFD, FD_CLOEXEC);
#endif
		data->out = fdopen(err, "w");
		if (data->out == NULL)
			goto io_file_error;
		break;

	case IO_TYPE_GET:
		err = open((char*)name, O_RDONLY|O_CLOEXEC);
		if (err == -1)
			goto io_file_error;
#if ! O_CLOEXEC
		(void)fcntl(err, F_SETFD, FD_CLOEXEC);
#endif
		data->in = fdopen(err, "r");
		if (data->in == NULL)
			goto io_file_error;
		if (feof(data->in))
			self->state |= IO_STATE_EOF;
		break;

	case IO_TYPE_XOBEX:
	default:
		return -ENOTSUP;
	}

	free(name);

	self->state |= IO_STATE_OPEN;

	return 0;

io_file_error:
	err = -errno;
	free(name);
	(void)io_file_close(self, transfer, true);
	
	return err;
}

static void io_file_cleanup (struct io_handler *self)
{
	if (self->private_data) {
		free(self->private_data);
		self->private_data = NULL;
	}
}

static ssize_t io_file_read(struct io_handler *self, void *buf, size_t bufsize)
{
	struct io_file_data *data = self->private_data;
	size_t status;

	if (!data->in)
		return -EBADF;

	if (bufsize == 0)
		return 0;

	if (buf == NULL)
		return -EINVAL;

	status = fread(buf, bufsize, 1, data->in);
	if (feof(data->in))
		self->state |= IO_STATE_EOF;

	if (status < bufsize && !feof(data->in))
		return -ferror(data->in);
	else
		return status;
}

static ssize_t io_file_write(struct io_handler *self, const void *buf, size_t len)
{
	struct io_file_data *data = self->private_data;
	size_t status;

	if (!data->out)
		return -EBADF;

	if (len == 0)
		return 0;

	if (buf == NULL)
		return -EINVAL;

	status = fwrite(buf, len, 1, data->out);
	if (status < len)
		return -ferror(data->out);
	else
		return status;
}

static struct io_handler* io_file_copy(struct io_handler *self)
{
	return io_file_init();
}

static struct io_handler_ops io_file_ops = {
	.open = io_file_open,
	.close = io_file_close,
	.copy = io_file_copy,
	.cleanup = io_file_cleanup,
	.read = io_file_read,
	.write = io_file_write,
};

struct io_handler * io_file_init() {
	struct io_handler *handle = malloc(sizeof(*handle));
	struct io_file_data *data = malloc(sizeof(*data));

	if (!handle || !data)
		return NULL;

	memset(handle, 0, sizeof(*handle));
	handle->ops = &io_file_ops;
	handle->private_data = data;

	memset(data, 0, sizeof(*data));

	return handle;
}
