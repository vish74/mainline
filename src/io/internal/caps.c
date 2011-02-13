
#include "common.h"
#include "caps.h"
#include "closexec.h"
#include "x-obex/obex-capability.h"

#include <errno.h>

static struct obex_capability caps = {
	.general = {
		.vendor = NULL,
		.model = NULL,
	},
};

int io_internal_caps_open (struct io_handler *self,
			   struct io_transfer_data *transfer)
{
	struct io_internal_data *data = self->private_data;
	int err = 0;

	data->in = tmpfile();
	if (data->in == NULL)
		return -errno;;
	set_closexec_flag(fileno(data->in));

	err = obex_capability(data->in, &caps);
	if (err)
		return err;;

	transfer->length = ftell(data->in);
	(void)fseek(data->in, 0L, SEEK_SET);
	return 0;
}
