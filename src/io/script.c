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

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#include "io.h"
#include "utf.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct io_script_data {
	pid_t child;
	const char* script;
	FILE *in;
	FILE *out;
};

static int io_script_close (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	bool keep
)
{
	struct io_script_data *data = self->private_data;

	if (data->child != (pid_t)-1) {
		int status;

		if (!keep) {
			/* signal 'undo' and give it time to react */
			kill(data->child, SIGUSR1);
			sleep(2);
		}
		kill(data->child, SIGKILL);
		if (waitpid(data->child, &status, 0) < 0)
			return -errno;

		data->child = (pid_t)-1;

		if (WIFEXITED(status)) {
			fprintf(stderr, "script exited with exit code %d\n", WEXITSTATUS(status));

		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "script got signal %d\n", WTERMSIG(status));
		}

	}

	if (data->in) {
		if (fclose(data->in) == EOF)
			return -errno;
		data->in = NULL;
	}

	if (data->out) {
		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;
	}
	self->state = 0;

	return 0;
}

static
int put_wait_for_ok (struct io_handler *self)
{
	char ret[4+1];
	ssize_t err;

	memset(ret, 0, sizeof(ret));
	err = io_readline(self, ret, sizeof(ret));
	if (err < 0)
		return err;

	if (strncmp(ret, "OK\n", 3) != 0 ||
	    strncmp(ret, "OK\r\n", 4) != 0)
		return -EPERM;
	else
		return 0;
}

static int io_script_open (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	enum io_type t
)
{
	int err = 0;
	int p[2] = { -1, -1};
	uint8_t* name = utf16to8(transfer->name);
	struct io_script_data *data = self->private_data;
	char* args[] = { (char*)data->script, NULL , NULL };

	switch (t) {
	case IO_TYPE_PUT:
		args[1] = "put";
		break;

	case IO_TYPE_GET:
		args[1] = "get";
		break;

	case IO_TYPE_XOBEX:
		args[1] = "xobex";
		break;

	default:
		return -ENOTSUP;
	}

	if (!name)
		return -EINVAL;

	err = io_script_close(self, transfer, true);
	if (err)
		return err;

	err = pipe_open(data->script, args, p, &data->child);
	if (err)
		return err;

	data->in = fdopen(p[0], "r");
	if (data->in)
		data->out = fdopen(p[1], "w");
	if (!data->in || !data->out) {
		err = errno;
		pipe_close(p);
		io_script_close(self, transfer, true);
		return -err;
	}

	self->state |= IO_STATE_OPEN;

	/* headers can be written here */
	if (transfer->peername && strlen(transfer->peername))
		fprintf(data->out, "From: %s\n", transfer->peername);
	switch (t) {
	case IO_TYPE_PUT:
		if (transfer->length)
			fprintf(data->out, "Length: %zu\n", transfer->length);
		if (transfer->time) {
			char tmp[17];
			struct tm t;
			
			(void)gmtime_r(&transfer->time, &t);
			memset(tmp, 0, 17);
			if (strftime(tmp, 17, "%Y%m%dT%H%M%SZ", &t) == 16) {
				fprintf(data->out, "Time: %s\n", tmp);
			}
		}
		/* no break */

	case IO_TYPE_GET:
		fprintf(data->out, "Name: %s\n", name);
		if (transfer->type)
			fprintf(data->out, "Type: %s\n", transfer->type);
		break;

	case IO_TYPE_XOBEX:
		fprintf(data->out, "X-OBEX-Type: %s\n", transfer->type+7);
		if (name)
			fprintf(data->out, "Type; %s\n", name);
		break;		
	}
	free(name);
	
	/* empty line signals that data follows */
	fprintf(data->out, "\n");
	fflush(data->out);
	if (feof(data->in))
		self->state |= IO_STATE_EOF;

	if (t == IO_TYPE_PUT)
		err = put_wait_for_ok(self);
	return err;
}

static void io_script_cleanup (struct io_handler *self)
{
	if (self->private_data) {
		free(self->private_data);
		self->private_data = NULL;
	}
}

static ssize_t io_script_read(struct io_handler *self, void *buf, size_t bufsize)
{
	struct io_script_data *data = self->private_data;
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

static ssize_t io_script_write(struct io_handler *self, const void *buf, size_t len)
{
	struct io_script_data *data = self->private_data;
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

static struct io_handler* io_script_copy(struct io_handler *self)
{
	struct io_script_data *data = self->private_data;

	return io_script_init(data->script);
}

static struct io_handler_ops io_script_ops = {
	.open = io_script_open,
	.close = io_script_close,
	.copy = io_script_copy,
	.cleanup = io_script_cleanup,
	.read = io_script_read,
	.write = io_script_write,
};

struct io_handler * io_script_init(const char* script) {
	struct io_handler *handle = malloc(sizeof(*handle));
	struct io_script_data *data = malloc(sizeof(*data));

	if (!handle || !data)
		return NULL;

	memset(handle, 0, sizeof(*handle));
	handle->ops = &io_script_ops;
	handle->private_data = data;

	memset(data, 0, sizeof(*data));
	data->child = (pid_t)-1;
	data->script = script;

	return handle;
}
