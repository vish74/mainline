#include "auth.h"
#include "utf.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "compiler.h"
#include "closexec.h"

struct auth_file_data {
	struct {
		char* filename;
		uint16_t *name;
		uint8_t opts;
	} realm[1];
};

static int get_realm_count (struct auth_handler *self)
{
	struct auth_file_data *data = self->private_data;
 
	if (!data)
		return 0;

	return sizeof(data->realm)/sizeof(data->realm[0]);
}

static int get_realm_id (struct auth_handler *self,
			 const uint16_t *realm)
{
	struct auth_file_data *data = self->private_data;
	unsigned int count = get_realm_count(self);
	unsigned int i = 0;

	for (; i < count; ++i) {
		if (realm == NULL) {
			if (data->realm[i].name == NULL)
				return i;
		} else {
			size_t size = ucs2len(data->realm[i].name);
			if (memcmp(realm, data->realm[i].name, size) == 0)
				return i;
		}
	}
	return -EINVAL;
}

static const uint16_t* get_realm_name (struct auth_handler *self,
				       int id)
{
	struct auth_file_data *data = self->private_data;

	if (id >= get_realm_count(self))
		return NULL;

	return data->realm[id].name;
}

static uint8_t get_realm_opts(struct auth_handler *self,
			      const uint16_t *realm)
{
	struct auth_file_data *data = self->private_data;
	int id = get_realm_id(self, realm);

	if (id >= 0)
		return data->realm[id].opts;
	else
		return 0;
}

static int verify (struct auth_handler *self,
		   const uint16_t *realm,
		   const uint8_t *user, size_t ulen,
		   auth_verify_cb cb, void *cb_data)
{
	struct auth_file_data *data = self->private_data;
	int id = get_realm_id(self, realm);
	int fd = -1;
	struct stat fdinfo;
	const uint8_t *start = MAP_FAILED;
	size_t mapsize = 0;
	int ret = 0;

	if (id < 0)
		goto out;

	fd = open_closexec(data->realm[id].filename, O_RDONLY, 0);
	if (fd == -1)
		goto out;

	/* user + separator ':' + pass (minimum length 1) + line end */
	if (fstat(fd, &fdinfo) != 0)
		goto out;
	mapsize =  (size_t)fdinfo.st_size;
	if (mapsize < ulen)
		goto out;

	start = mmap(NULL, mapsize, PROT_READ, MAP_SHARED, fd, 0);
	if (start != MAP_FAILED) {
		const uint8_t *cur = start;
		const uint8_t *end = start + mapsize;
		
		while ((cur + ulen + 1) <= end) {
			if (memcmp(cur, user, ulen) != 0 || cur[ulen] != ':') {
				/* no match, skip current line or go to end of file */
				while (cur != end && *cur != '\n')
					++cur;
				if (cur != end)
					++cur;

			} else {
				/* user matched */
				const uint8_t *pass = cur + ulen + 1;
				size_t plen = 0;

				/* forward to end of line or end of file */
				cur = pass;
				while (cur != end && *cur != '\n')
					++cur;
				if (cur != end)
					++cur;

				/* remove line end characters */
				plen = cur - pass;
				if (pass[plen] == '\n') {
					if (pass[--plen] == '\r')
						--plen;
				}

				/* verify using callback function */
				ret = cb(cb_data, pass, plen);
				break;
			}
		}
	}

out:
	if (start != MAP_FAILED)
		(void)munmap((void*)start, mapsize);
	if (fd >= 0)
		close(fd);
	return ret;
}

static struct auth_handler* auth_file_copy (struct auth_handler *self)
{
	struct auth_file_data *data = self->private_data;

	return auth_file_init(data->realm[0].filename,
			      data->realm[0].name,
			      data->realm[0].opts);
}

static void auth_file_cleanup (struct auth_handler *self)
{
	struct auth_file_data *data = self->private_data;
	unsigned int count = get_realm_count(self);
	unsigned int i = 0;

	if (!data)
		return;

	for (; i < count; ++i) {
		if (data->realm[i].filename)
			free(data->realm[i].filename);
		if (data->realm[i].name)
			free(data->realm[i].name);
	}
	memset(data, 0, sizeof(data));
	free(data);
	self->private_data = NULL;
}

static struct auth_handler_ops auth_file_ops = {
	.get_realm_count = get_realm_count,
	.get_realm_name = get_realm_name,
	.get_realm_opts = get_realm_opts,
	.verify = verify,
	.copy = auth_file_copy,
	.cleanup = auth_file_cleanup,
};

struct auth_handler* auth_file_init (char* file, uint16_t *realm, uint8_t opts)
{
	struct auth_handler *h = malloc(sizeof(*h));
	
	if (h) {
		struct auth_file_data *d = malloc(sizeof(*d));

		memset(h, 0, sizeof(*h));
		h->ops = &auth_file_ops;
		h->private_data = d;

		if (!d)
			goto out;

		memset(d, 0, sizeof(*d));
		d->realm[0].filename = strdup(file);
		if (!d->realm[0].filename)
			goto out;

		if (realm) {
			d->realm[0].name = ucs2dup(realm);
			if (!d->realm[0].name)
				goto out;
		}
		
		d->realm[0].opts = opts;	

		h->session = malloc(get_realm_count(h) * sizeof(*h->session));
		if (!h->session)
			goto out;
	}

	return h;

out:
	if (h) {
		auth_file_cleanup(h);
		if (h->session) {
			free(h->session);
			h->session = NULL;
		}
		free(h);
	}
	return NULL;
}
