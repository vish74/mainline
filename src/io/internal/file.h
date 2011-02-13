
#include <sys/types.h>
#include "io.h"

int io_internal_open_put (struct io_handler *self,
			  struct io_transfer_data *transfer,
			  const char *name);
int io_internal_open_get (struct io_handler *self,
			  struct io_transfer_data *transfer,
			  const char *name);
int io_internal_file_delete (struct io_handler *self, const char *name);
void io_internal_file_close (struct io_handler *self,
			     struct io_transfer_data *transfer,
			     const char *name);
ssize_t io_internal_file_read (struct io_handler *self,
			       void *buf, size_t bufsize);
ssize_t io_internal_file_write (struct io_handler *self,
				const void *buf, size_t len);
