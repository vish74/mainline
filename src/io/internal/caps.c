
#include "common.h"
#include "caps.h"
#include "closexec.h"
#include "x-obex/obex-capability.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>

static struct obex_capability caps = {
	.general = {
		.vendor = NULL,
		.model = NULL,
	},
};

static bool ismount (const char* path)
{
	bool result = false;
	struct stat info1;

	if (strcmp(path, "/") == 0)
	    return true;

	if (stat(path, &info1) == 0 &&
	    S_ISDIR(info1.st_mode))
	{
		struct stat info2;

		char *p = strdup(path);
		const char *parent = dirname(p);

		if (stat(parent, &info2) == 0)
			result = (info1.st_dev != info2.st_dev);

		free(p);
	}

	return result;
}

static bool set_memory_capability(const char *tpath, struct obex_caps_mem *mem)
{
	bool result = false;
	struct statvfs meminfo;
	char *p = strdup(tpath);
	char *path = p;

	memset(mem, 0, sizeof(*mem));
	mem->file.size_max = ULONG_MAX;
	mem->folder.size_max = ULONG_MAX;

	if (!path)
		return false;

	/* walk up the path until it is a mount point or our root */
	while (strcmp(path, ".") != 0 && !ismount(path))
		path = dirname(path);

	if (statvfs(path, &meminfo) == 0)
	{
		if (strlen(path) &&
		    (strcmp(path, ".") != 0 || strcmp(path, "/") != 0))
		{
			if (path[0] == '/')
				mem->location = strdup(path + 1);
			else
				mem->location = strdup(path);
		}
		mem->free = meminfo.f_bavail * meminfo.f_bsize;
		mem->used = (meminfo.f_blocks - meminfo.f_bavail) * meminfo.f_bsize;
		mem->file.namelen_max = meminfo.f_namemax;
		mem->folder.namelen_max = meminfo.f_namemax;

		result = true;
	}

	if (p)
		free(p);

	return result;
}

static void clear_memory_capability(struct obex_caps_mem *mem)
{
	if (mem->location)
		free(mem->location);
	mem->location = 0;
}

int io_internal_caps_open (struct io_handler *self,
			   struct io_transfer_data *transfer,
			   const char *name)
{
	struct io_internal_data *data = self->private_data;
	struct obex_caps_mem caps_mem;
	int err = 0;

	data->in = tmpfile();
	if (data->in == NULL)
		return -errno;;
	set_closexec_flag(fileno(data->in));

	if (set_memory_capability(name, &caps_mem))
	{
		caps.general.mem = &caps_mem;
		caps.general.mem_count = 1;
	}

	err = obex_capability(data->in, &caps);

	caps.general.mem = NULL;
	caps.general.mem_count = 0;
	clear_memory_capability(&caps_mem);

	if (err)
		return err;;

	transfer->length = ftell(data->in);
	(void)fseek(data->in, 0L, SEEK_SET);
	return 0;
}
