#include "checks.h"
#include "common.h"
#include "file.h"

#ifdef USE_XATTR
#include <attr/xattr.h>
#endif
#include <sys/types.h>
#include <string.h>
#include <utime.h>

#include "closexec.h"
#include "compiler.h"

static void io_internal_file_set_time (const char *name, time_t time)
{
	struct utimbuf times;
					
	times.actime = time;
	times.modtime = time;
	/* setting the time is non-critical */
	(void)utime(name, &times);
}

#ifdef USE_XATTR
static void io_internal_file_set_type (const char *name, const char *type)
{
	(void)lsetxattr(name, "user.mime_type", type, strlen(type)+1, 0);
}

static char * io_internal_file_get_type (const char *name)
{	
	char type[256];
	ssize_t status = lgetxattr(name, "user.mime_type", type, sizeof(type));

	if (status < 0 ||
	    strlen(type) != (size_t)status ||
	    !check_type(type))
		return NULL;

	return strdup(type);
}
#endif

int io_internal_open_put (struct io_handler *self,
			  struct io_transfer_data *transfer,
			  const char *name)
{
	struct io_internal_data *data = self->private_data;
	int err = 0;

	if (!transfer->name)
		return -EINVAL;

	fprintf(stderr, "Creating file \"%s\"\n", name);
	err = open_closexec(name, O_WRONLY|O_CREAT|O_EXCL,
			    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if (err == -1)
		return -errno;

	if (transfer->length)
		(void)posix_fallocate(err, 0, transfer->length);

	data->out = fdopen(err, "w");
	if (data->out == NULL)
		return -errno;

	return 0;
}

int io_internal_open_get (struct io_handler *self,
			  struct io_transfer_data *transfer,
			  const char *name)
{
	struct io_internal_data *data = self->private_data;
	int err = 0;
	struct stat s;

	if (!transfer->name)
		return -EINVAL;

	err = open_closexec(name, O_RDONLY, 0);
	if (err == -1)
		return -errno;;

	data->in = fdopen(err, "r");
	if (data->in == NULL)
		return -errno;

#ifdef USE_XATTR
	transfer->type = io_internal_file_get_type(name);
#endif
	if (fstat(err, &s) == -1)
		return 0;

	transfer->length = s.st_size;
	transfer->time = s.st_mtime;
	return 0;
}

int io_internal_file_delete (struct io_handler __unused *self, const char *name)
{
	/* remove the file */
	fprintf(stderr, "Deleting file \"%s\"\n", name);
	if (unlink(name) == -1) 
		return -errno;

	return 0;
}

void io_internal_file_close (struct io_handler __unused *self,
			    struct io_transfer_data *transfer,
			    const char *name)
{
	if (transfer->time)
		io_internal_file_set_time(name, transfer->time);
#ifdef USE_XATTR
	if (transfer->type)
		io_internal_file_set_type(name, transfer->type);
#endif
}

ssize_t io_internal_file_read (struct io_handler *self,
			       void *buf, size_t bufsize)
{
	struct io_internal_data *data = self->private_data;
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

ssize_t io_internal_file_write (struct io_handler *self,
				const void *buf, size_t len)
{
	struct io_internal_data *data = self->private_data;
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
