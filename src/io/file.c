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

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <utime.h>
#ifdef USE_XATTR
#include <attr/xattr.h>
#endif

#include "io.h"
#include "utf.h"
#include "net.h"
#include "closexec.h"
#include "x-obex/obex-capability.h"
#include "x-obex/obex-folder-listing.h"

struct io_file_data {
	char *basedir;

	FILE *in;
	FILE *out;
};

static char* io_file_get_fullname(const char *basedir, const char *subdir, const uint16_t *filename)
{
	uint8_t *namebase = NULL;
	int err = 0;
	char *name;
	size_t namesize;

	if (filename) {
		namebase = utf16to8(filename);
		if (!namebase)
			return NULL;
	}

	namesize = strlen(basedir) + 1 + utf8len((uint8_t*)subdir) + 1 + utf8len(namebase) + 1;
	name = malloc(namesize);
	if (!name)
		err = -errno;
	else {
		memset(name, 0, namesize);
		if (strcmp(basedir, ".") != 0) {
			strcat(name, basedir);
		}
		if (utf8len((uint8_t*)subdir)) {
			if (utf8len((uint8_t*)name))
				strcat(name, "/");
			strcat(name, subdir);
		}
		if (utf8len(namebase)) {
			if (utf8len((uint8_t*)name))
				strcat(name, "/");
			strcat(name, (char*)namebase);

		} else if (utf8len((uint8_t*)name) == 0)
			strcat(name, basedir);
	}
	free(namebase);
	if (err)
		errno = -err;
	return name;
}

static int io_file_delete (
	struct io_handler *self,
	struct io_transfer_data *transfer
)
{
	struct io_file_data *data = self->private_data;
	char* name;
	int err = 0;

	if (!transfer)
		return -EINVAL;

	name = io_file_get_fullname(data->basedir, transfer->path, transfer->name);
	if (!name)
		err = -ENOMEM;
	else {
		/* remove the file */
		fprintf(stderr, "Deleting file \"%s\"\n", name);
		if (unlink(name) == -1) 
			err = -errno;
		free(name);
	}

	return 0;
}

static void io_file_set_time (
	const char *name,
	time_t time
)
{
	struct utimbuf times;
					
	times.actime = time;
	times.modtime = time;
	/* setting the time is non-critical */
	(void)utime(name, &times);
}

#ifdef USE_XATTR
static void io_file_set_type (
	const char *name,
	const char *type
)
{
	(void)lsetxattr(name, "user.mime_type", type, strlen(type)+1, 0);
}

static char * io_file_get_type (
	const char *name
)
{	
	char type[256];
	ssize_t status = lgetxattr(name, "user.mime_type", type, sizeof(type));

	if (status < 0 ||
	    strlen(type) != (size_t)status ||
	    !check_type((uint8_t*)type))
		return NULL;

	return strdup(type);
}
#endif

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
		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;

		if (transfer) {
			if (!keep) {
				io_file_delete(self, transfer);

			} else if (transfer->time || transfer->type) {
				char *name = io_file_get_fullname(data->basedir,
								  transfer->path,
								  transfer->name);
				if (!name)
					return 0;

				if (transfer->time)
					io_file_set_time(name, transfer->time);
#ifdef USE_XATTR
				if (transfer->type)
					io_file_set_type(name, transfer->type);
#endif
				free(name);
			}
		}
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
	int err = 0;
	char *name = NULL;
	struct io_file_data *data = self->private_data;
	struct stat s;

	err = io_file_close(self, NULL, true);
	if (err)
		return err;

	name = io_file_get_fullname(data->basedir, transfer->path, transfer->name);
	if (!name)
		return -errno;

	switch (t) {
	case IO_TYPE_PUT:
		if (!transfer->name)
			return -EINVAL;
		fprintf(stderr, "Creating file \"%s\"\n", name);
		err = open_closexec(name, O_WRONLY|O_CREAT|O_EXCL,
				    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		if (err == -1) {
			fprintf(stderr, "Error: cannot create file: %s\n", strerror(-err));
			goto io_file_error;
		}
		if (transfer->length)
			(void)posix_fallocate(err, 0, transfer->length);

		data->out = fdopen(err, "w");
		if (data->out == NULL)
			goto io_file_error;
		break;

	case IO_TYPE_GET:
		if (!transfer->name)
			return -EINVAL;
		err = open_closexec(name, O_RDONLY, 0);
		if (err == -1)
			goto io_file_error;

		data->in = fdopen(err, "r");
		if (data->in == NULL)
			goto io_file_error;
		if (fstat(err, &s) == -1)
			return -errno;
		transfer->length = s.st_size;
		transfer->time = s.st_mtime;
#ifdef USE_XATTR
		transfer->type = io_file_get_type(name);
#endif
		break;

	case IO_TYPE_LISTDIR:
		data->in = tmpfile();
		if (data->in == NULL)
			goto io_file_error;
		else {
			int flags = OFL_FLAG_TIMES | OFL_FLAG_PERMS | OFL_FLAG_KEEP;

			if (utf8len((uint8_t*)transfer->path))
				flags |= OFL_FLAG_PARENT;
			err = obex_folder_listing(data->in, name, flags);
			if (err)
				goto out;
		}
		transfer->length = ftell(data->in);
		(void)fseek(data->in, 0L, SEEK_SET);
		break;

	case IO_TYPE_CAPS:
		data->in = tmpfile();
		if (data->in == NULL)
			goto io_file_error;
		else {
			struct obex_capability caps = {
				.general = {
					.vendor = NULL,
					.model = NULL,
				},
			};
			err = obex_capability(data->in, &caps);
			if (err)
				goto out;
		}
		transfer->length = ftell(data->in);
		(void)fseek(data->in, 0L, SEEK_SET);
		break;

	default:
		err = -EINVAL;
		goto out;
	}

	free(name);
	self->state |= IO_STATE_OPEN;

	return 0;

io_file_error:
	err = -errno;
out:
	free(name);
	(void)io_file_close(self, transfer, (err != -EEXIST));
	
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

	if (status != 1 && !feof(data->in))
		return -ferror(data->in);
	else
		return status*bufsize;
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

static int io_file_check_dir(struct io_handler *self, const char *dir)
{
	struct io_file_data *data = self->private_data;
	char *fulldir = io_file_get_fullname(data->basedir, dir, NULL);
	struct stat s;
	int err = 0;

	if (!fulldir)
		err = -errno;
	else if (stat(fulldir, &s) == -1)
		err = -errno;
	else if (!S_ISDIR(s.st_mode))
		err = -ENOTDIR;
	free(fulldir);

	return err;
}

static int io_file_create_dir(struct io_handler *self, const char *dir)
{
	struct io_file_data *data = self->private_data;
	char *fulldir = io_file_get_fullname(data->basedir, dir, NULL);
	int err = 0;

	if (!fulldir)
		err = -errno;
	else if (io_file_check_dir(self, dir) != 0) {
		fprintf(stderr, "Creating directory \"%s\"\n", fulldir);
		if (mkdir(fulldir, S_IRWXU|S_IRWXG|S_IRWXO) == -1) {
			fprintf(stderr, "Error: cannot create directory: %s\n", strerror(-err));
			err = -errno;
		}
	}
	
	return 0;
}

static struct io_handler* io_file_copy(struct io_handler *self)
{
	struct io_file_data *data = self->private_data;

	return io_file_init(data->basedir);
}

static struct io_handler_ops io_file_ops = {
	.open = io_file_open,
	.close = io_file_close,
	.delete = io_file_delete,
	.copy = io_file_copy,
	.cleanup = io_file_cleanup,
	.read = io_file_read,
	.write = io_file_write,
	.check_dir = io_file_check_dir,
	.create_dir = io_file_create_dir,
};

struct io_handler * io_file_init(const char *basedir) {
	struct io_handler *handle = NULL;
	struct io_file_data *data = NULL;

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
