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

#include "checks.h"

#include "common.h"
#include "file.h"
#include "dir.h"
#include "caps.h"

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "io.h"
#include "utf.h"
#include "net.h"

char* io_internal_get_fullname(const char *basedir, const uint8_t *subdir,
			       const uint8_t *namebase)
{
	int err = 0;
	char *name;
	size_t namesize;

	if (!namebase)
		return NULL;

	namesize = strlen(basedir) + 1 + utf8len(subdir) + 1 + utf8len(namebase) + 1;
	name = malloc(namesize);
	if (!name)
		err = -errno;
	else {
		memset(name, 0, namesize);
		if (strcmp(basedir, ".") != 0) {
			strcat(name, basedir);
		}
		if (utf8len(subdir)) {
			if (utf8len((uint8_t*)name))
				strcat(name, "/");
			strcat(name, (char*)subdir);
		}
		if (utf8len(namebase)) {
			if (utf8len((uint8_t*)name))
				strcat(name, "/");
			strcat(name, (char*)namebase);

		} else if (utf8len((uint8_t*)name) == 0)
			strcat(name, basedir);
	}

	if (err)
		errno = -err;
	return name;
}

static int io_internal_delete (struct io_handler *self,
			       struct io_transfer_data *transfer)
{
	struct io_internal_data *data = self->private_data;
	char* name;
	int err = 0;

	if (!transfer)
		return -EINVAL;

	name = io_internal_get_fullname(data->basedir, transfer->path, transfer->name);
	if (!name)
		return -ENOMEM;

	err = io_internal_file_delete(self, name);
	free(name);
	return err;
}

static int io_internal_close (struct io_handler *self,
			      struct io_transfer_data *transfer,
			      bool keep)
{
	struct io_internal_data *data = self->private_data;

	if (data->in) {
		if (fclose(data->in) == EOF)
			return -errno;
		data->in = NULL;
	}

	if (data->out) {
		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;

		if (transfer) {
			char *name = io_internal_get_fullname(data->basedir,
							      transfer->path,
							      transfer->name);
			if (!name)
				return -errno;

			if (!keep)
				io_internal_file_delete(self, name);
			else 
				io_internal_file_close(self, transfer, name);
			free(name);
		}
	}
	self->state = 0;

	return 0;
}

static int io_internal_open (struct io_handler *self,
			     struct io_transfer_data *transfer,
			     enum io_type t)
{
	int err = 0;
	char *name = NULL;
	struct io_internal_data *data = self->private_data;

	err = io_internal_close(self, NULL, true);
	if (err)
		return err;

	name = io_internal_get_fullname(data->basedir, transfer->path, transfer->name);
	if (!name)
		return -errno;

	switch (t) {
	case IO_TYPE_PUT:
		err = io_internal_open_put(self, transfer, name);
		if (err)
			fprintf(stderr, "Error: cannot create file: %s\n", strerror(-err));
		break;

	case IO_TYPE_GET:
		err = io_internal_open_get(self, transfer, name);
		break;

	case IO_TYPE_LISTDIR:
		err = io_internal_dir_open(self, transfer, name);
		break;

	case IO_TYPE_CAPS:
		err = io_internal_caps_open(self, transfer);
		break;

	default:
		err = -EINVAL;
		break;
	}

	free(name);
	if (err) {
		(void)io_internal_close(self, transfer, (err != -EEXIST));
	} else {
		self->state |= IO_STATE_OPEN;
	}

	return err;
}

static void io_internal_cleanup (struct io_handler *self)
{
	if (self->private_data) {
		free(self->private_data);
		self->private_data = NULL;
	}
}

static struct io_handler* io_internal_copy(struct io_handler *self)
{
	struct io_internal_data *data = self->private_data;

	return io_file_init(data->basedir);
}

static struct io_handler_ops io_file_ops = {
	.copy = io_internal_copy,
	.cleanup = io_internal_cleanup,

	.open = io_internal_open,
	.close = io_internal_close,
	.delete = io_internal_delete,
	.read = io_internal_file_read,
	.write = io_internal_file_write,

	.check_dir = io_internal_dir_check,
	.create_dir = io_internal_dir_create,
};

struct io_handler * io_file_init(const char *basedir) {
	struct io_handler *handle = NULL;
	struct io_internal_data *data = NULL;

	if (!basedir || strlen(basedir) == 0) {
		errno = EINVAL;
		goto out;
	}

	handle = malloc(sizeof(*handle));
	if (!handle)
		goto out;
	memset(handle, 0, sizeof(*handle));
	handle->ops = &io_file_ops;

	data = malloc(sizeof(*data));
	if (!data)
		goto out_err;
	memset(data, 0, sizeof(*data));
	data->basedir = strdup(basedir);
	if (!data->basedir)
		goto out_err;
	handle->private_data = data;


	return handle;

out_err:
	{
		int err = errno;
		if (data) {
			if (data->basedir)
				free(data->basedir);
			free(data);
		}
		if (handle) {
			free(handle);
		}
		errno = err;
	}
out:
	return NULL;
}
