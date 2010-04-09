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

#include "io.h"
#include "errno.h"

#include <stdlib.h>
#include <string.h>

struct io_handler * io_copy (
	struct io_handler *h
)
{
	if (!h)
		return NULL;

	if (h && h->ops && h->ops->copy) {
		/* deep copy */
		return h->ops->copy(h);

	} else {
		/* flat copy */
		struct io_handler *hnew = malloc(sizeof(*hnew));
		if (hnew)
			memcpy(hnew, h, sizeof(*hnew));
		return hnew;
	}
}

void io_destroy (struct io_handler* h)
{
	if (h) {
		if (h->ops && h->ops->cleanup)
			h->ops->cleanup(h);
		free(h);
	}
}

unsigned long io_state(
	struct io_handler *self
)
{
	if (!self)
		return 0;
	else
		return self->state;
}

int io_open (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	enum io_type t
)
{
	if (!self)
		return -EBADF;

	if (self->ops && self->ops->open)
		return self->ops->open(self, transfer, t);
	else
		return 0;
}

int io_close (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	bool keep
)
{
	if (!self)
		return -EBADF;

	if (self->ops && self->ops->close)
		return self->ops->close(self, transfer, keep);
	else
		return 0;
}

int io_delete (
	struct io_handler *self,
	struct io_transfer_data *transfer
)
{
	if (!self)
		return -EBADF;

	if (self->ops && self->ops->delete)
		return self->ops->delete(self, transfer);
	else
		return 0;
}

ssize_t io_readline(struct io_handler *self, void *buf, size_t bufsize) {
	ssize_t retval = 0;
	ssize_t err;
	char *cbuf = buf;

	if (bufsize == 0)
		return 0;

	do {
		char tmp;

		err = io_read(self, &tmp, 1);
		if (err < 0) {
			retval = err;
		} else if (err > 0) {
			*cbuf = tmp;
			++retval;
		}
	} while (--bufsize && *(cbuf++) != '\n' && err > 0);

	return retval;
}

ssize_t io_read(
	struct io_handler *self,
	void *buf,
	size_t bufsize
)
{
	if (!self)
		return -EBADF;

	if (bufsize == 0)
		return 0;

	if (self->ops && self->ops->read)
		return self->ops->read(self, buf, bufsize);
	else
		return 0;
}

ssize_t io_write(
	struct io_handler *self,
	const void *buf,
	size_t len
)
{
	if (!self)
		return -EBADF;

	if (len == 0)
		return 0;

	if (self->ops && self->ops->write)
		return self->ops->write(self, buf, len);
	else
		return 0;
}

int io_check_dir(
	struct io_handler *self,
	const char *dir
)
{
	if (!self)
		return -EBADF;

	if (self->ops && self->ops->check_dir)
		return self->ops->check_dir(self, dir);
	else
		return 0;
}

int io_create_dir(
	struct io_handler *self,
	const char *dir
)
{
	if (!self)
		return -EBADF;

	if (self->ops && self->ops->create_dir)
		return self->ops->create_dir(self, dir);
	else
		return -EFAULT;
}
