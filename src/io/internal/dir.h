
#include "io.h"

int io_internal_dir_open(struct io_handler *self,
			 struct io_transfer_data *transfer,
			 char *name);
int io_internal_dir_check(struct io_handler *self, const char *dir);
int io_internal_dir_create(struct io_handler *self, const char *dir);
