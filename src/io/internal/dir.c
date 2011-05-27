
#include "common.h"
#include "dir.h"
#include "closexec.h"
#include "utf.h"
#include "x-obex/obex-folder-listing.h"

#include <errno.h>
#include <string.h>

int io_internal_dir_open(struct io_handler *self,
			 struct io_transfer_data *transfer,
			 char *name)
{
	struct io_internal_data *data = self->private_data;
	int flags = OFL_FLAG_TIMES | OFL_FLAG_PERMS | OFL_FLAG_KEEP;
	struct stat s;
	int err = 0;

	data->in = tmpfile();
	if (data->in == NULL)
		return -errno;
	set_closexec_flag(fileno(data->in));


	if (utf8len((uint8_t*)transfer->path))
		flags |= OFL_FLAG_PARENT;
	err = obex_folder_listing(data->in, name, flags);
	if (err)
		return err;

	/* stating dir to get last modification time */
	if (fstat(err, &s) == -1)
		return -errno;

	transfer->length = ftell(data->in);
	transfer->time = s.st_mtime;

	/* rewinding to start of file */
	(void)fseek(data->in, 0L, SEEK_SET);

	return err;
}

int io_internal_dir_check(struct io_handler *self, const uint8_t *dir)
{
	struct io_internal_data *data = self->private_data;
	char *fulldir = io_internal_get_fullname(data->basedir, dir, NULL);
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

int io_internal_dir_create(struct io_handler *self, const uint8_t *dir)
{
	struct io_internal_data *data = self->private_data;
	char *fulldir = io_internal_get_fullname(data->basedir, dir, NULL);
	int err = 0;

	if (!fulldir)
	        return -errno;
	
	if (io_internal_dir_check(self, dir) != 0) {
		fprintf(stderr, "Creating directory \"%s\"\n", fulldir);
		if (mkdir(fulldir, S_IRWXU|S_IRWXG|S_IRWXO) == -1) {
			err = -errno;
			fprintf(stderr, "Error: %s: %s\n",
				"cannot create directory",
				strerror(-err));
		}
	}
	
	return 0;
}
