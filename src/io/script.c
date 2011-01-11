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

#include "obexpushd.h"
#include "checks.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <limits.h>

#include "io.h"
#include "utf.h"
#include "compiler.h"

struct io_script_data {
	pid_t child;
	const char* script;
	FILE *in;
	FILE *out;
};

static int io_script_exit (
	pid_t child,
	bool keep
)
{
	int status;
	int retval = 0;
	int pid = 0;

	if (!keep)
		kill(child, SIGUSR1); /* signal 'undo' */

	for (int i = 0; pid == 0 && i < 10; ++i) {
		pid = waitpid(child, &status, WNOHANG);
		if (pid == 0)
			sleep(1);
	}

	/* it not dead yet, kill it */
	if (pid == 0) {
		kill(child, SIGKILL);
		pid = waitpid(child, &status, 0);
	}

	if (pid < 0)
		retval = -errno;
	else if (WIFEXITED(status)) {
		retval = WEXITSTATUS(status);
		/* fprintf(stderr, "script exited with exit code %d\n", retval); */
	} else if (WIFSIGNALED(status) && keep) {
		retval = WTERMSIG(status);
		/* fprintf(stderr, "script got signal %d\n", retval); */
	}

	return retval;
}

static int io_script_close (
	struct io_handler *self,
	struct io_transfer_data __unused *transfer,
	bool keep
)
{
	struct io_script_data *data = self->private_data;
	int retval = 0;

	/* kill STDIN first to signal the script that there will be no more
	 * data */
	if (data->out) {
		if (fclose(data->out) == EOF)
			retval = -errno;
		else
			data->out = NULL;
	}

	if (data->child != (pid_t)-1) {
		retval = io_script_exit(data->child, keep);
		data->child = (pid_t)-1;
	}

	if (data->in) {
		if (fclose(data->in) == EOF)
			retval = -errno;
		else
			data->in = NULL;
	}
	self->state = 0;

	return retval;
}

static
int put_wait_for_ok (struct io_handler *self)
{
	char ret[4+1];
	ssize_t err;

	memset(ret, 0, sizeof(ret));
	err = io_readline(self, ret, sizeof(ret));
	if (err < 0)
		return err;

	if (strncmp(ret, "OK\n", 3) != 0 &&
	    strncmp(ret, "OK\r\n", 4) != 0)
		return -EPERM;
	else
		return 0;
}

#define EOL(n) ((n) == '\n' || (n) == '\r')

static
int io_script_parse_headers (
	struct io_handler *self,
	struct io_transfer_data *transfer
)
{
	char buffer[512+1];

	while (1) {
		size_t len = 0;
		int err;

		memset(buffer, 0, sizeof(buffer));
		err = io_readline(self, buffer, sizeof(buffer));
		if (err < 0) {
			return err;
		} else if (err == 0) {
			return -EINVAL;
		}
		len = strlen(buffer);

		if (len == 0 || !EOL(buffer[len-1]))
			return -EINVAL;
		
		if (len && buffer[len-1] == '\n')
			--len;
		if (len && buffer[len-1] == '\r')
			--len;
		buffer[len] = 0;

		/* stop on the first empty line */
		if (len == 0)
			break;

		/* compare the first part of buffer with known headers
		 * and ignore unknown ones
		 */
		if (strncasecmp(buffer,"Name: ",6) == 0) {
			uint8_t *name = (uint8_t*)(buffer+6);
			if (!check_name(name))
				return -EINVAL;
			if (transfer->name)
				free(transfer->name);
			transfer->name = utf8to16(name);

		} else if (strncasecmp(buffer,"Length: ",8) == 0) {
			char* endptr;
			long dlen = strtol(buffer+8, &endptr, 10);

			if ((dlen == LONG_MIN || dlen == LONG_MAX) && errno == ERANGE)
				return -errno;

			if (endptr != 0 && (0 <= dlen && dlen <= UINT32_MAX)) {
				transfer->length = (size_t)dlen;
				continue;
			}

		} else if (strncasecmp(buffer,"Type: ",6) == 0) {
			char* type = buffer+6;
			if (!check_type((uint8_t*)type))
				return -EINVAL;
			if (transfer->type)
				free(transfer->type);
			transfer->type = strdup(type);

		} else if (strncasecmp(buffer, "Time: ", 6) == 0) {
			char* timestr = buffer+6;
			struct tm time;

			tzset();
			/* uses GNU extensions */
			strptime(timestr, "%Y-%m-%dT%H:%M:%S", &time);
			time.tm_isdst = -1;
			transfer->time = mktime(&time);
			if (strlen(timestr) > 17 && timestr[17] == 'Z')
				transfer->time -= timezone;

		} else
			continue;
	}
	return 0;
}

static int io_script_prepare_cmd (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	const char *cmd
)
{
	int p[2] = { -1, -1};
	struct io_script_data *data = self->private_data;
	char* args[] = {(char*)data->script, (char*)cmd, NULL};

	int err = io_script_close(self, transfer, true);
	if (err)
		return err;

	err = pipe_open(data->script, args, p, &data->child);
	if (err)
		return err;

	data->in = fdopen(p[0], "r");
	if (data->in)
		data->out = fdopen(p[1], "w");
	if (!data->in || !data->out) {
		err = errno;
		pipe_close(p);
		io_script_close(self, transfer, true);
		return -err;
	}

	self->state |= IO_STATE_OPEN;

	return err;
}

static void str_subst(char *str, char a, char b)
{
	while(*str) {
		if (*str == a)
			*str = b;
		++str;
	}
}

#define IO_HT_FROM   (1 << 0)
#define IO_HT_LENGTH (1 << 1)
#define IO_HT_TIME   (1 << 2)
#define IO_HT_NAME   (1 << 3)
#define IO_HT_TYPE   (1 << 4)
#define IO_HT_PATH   (1 << 5)

static void io_script_write_headers (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	int ht
)
{
	struct io_script_data *data = self->private_data;

	if (ht & IO_HT_FROM) {
		if (transfer->peername && strlen(transfer->peername))
			fprintf(data->out, "From: %s\n", transfer->peername);
	}

	if (ht & IO_HT_LENGTH) {
		if (transfer->length)
			fprintf(data->out, "Length: %zu\n", transfer->length);
	}

	if (ht & IO_HT_TIME) {
		if (transfer->time) {
			char tmp[17];
			struct tm t;
			
			(void)gmtime_r(&transfer->time, &t);
			memset(tmp, 0, 17);
			if (strftime(tmp, 17, "%Y%m%dT%H%M%SZ", &t) == 16) {
				fprintf(data->out, "Time: %s\n", tmp);
			}
		}
	}

	if (ht & IO_HT_NAME) {
		char *str = (char*)utf16to8(transfer->name);
		if (str) {
			str_subst(str, '\n', ' ');
			fprintf(data->out, "Name: %s\n", str);
			free(str);
		}
	}

	if (ht & IO_HT_TYPE) {
		if (transfer->type) {
			char *str = strdup(transfer->type);
			if (str) {
				str_subst(str, '\n', ' ');
				fprintf(data->out, "Type: %s\n", str);
				free(str);
			}
		}
	}

	if (ht & IO_HT_PATH) {
		if (transfer->path) {
			char *str = strdup(transfer->path);
			if (str) {
				str_subst(str, '\n', ' ');
				fprintf(data->out, "Path: %s\n", str);
				free(str);
			}
		} else
			fprintf(data->out, "Path: .\n");
	}
	
	/* empty line signals that data follows */
	fprintf(data->out, "\n");
	fflush(data->out);
}

static int io_script_open (
	struct io_handler *self,
	struct io_transfer_data *transfer,
	enum io_type t
)
{
	struct io_script_data *data = self->private_data;
	const char *cmd;
	int ht = IO_HT_FROM;
	int err;

	switch (t) {
	case IO_TYPE_PUT:
		cmd = "put";
		ht |= IO_HT_LENGTH | IO_HT_TIME | IO_HT_NAME | IO_HT_TYPE | IO_HT_PATH;
		break;

	case IO_TYPE_GET:
		cmd = "get";
		ht |= IO_HT_PATH;
		if (transfer->name)
			ht |= IO_HT_NAME;
		else if (transfer->type)
			ht |= IO_HT_TYPE;
		else
			return -EINVAL;
		break;

	case IO_TYPE_LISTDIR:
		cmd = "listdir";
		ht |= IO_HT_PATH;		
		break;

	case IO_TYPE_CAPS:
		cmd = "capability";
		break;

	default:
		return -ENOTSUP;
	}

	err = io_script_prepare_cmd(self, transfer, cmd);
	if (!err)
		io_script_write_headers(self, transfer, ht);
	if (err)
		return err;
	if (feof(data->in))
		self->state |= IO_STATE_EOF;

	switch (t) {
	case IO_TYPE_PUT:
		err = put_wait_for_ok(self);
		break;

	default:
		err = io_script_parse_headers(self, transfer);
		break;
	}

	return err;
}

static void io_script_cleanup (struct io_handler *self)
{
	if (self->private_data) {
		free(self->private_data);
		self->private_data = NULL;
	}
}

static ssize_t io_script_read(struct io_handler *self, void *buf, size_t bufsize)
{
	struct io_script_data *data = self->private_data;
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

static ssize_t io_script_write(struct io_handler *self, const void *buf, size_t len)
{
	struct io_script_data *data = self->private_data;
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

static int io_script_create_dir(struct io_handler *self, const char *dir)
{
	struct io_script_data *data = self->private_data;
	struct io_transfer_data transfer;
	int err;

	transfer.path = strdup(dir),
	err = io_script_prepare_cmd(self, &transfer, "createdir");
	if (!err) {
		io_script_write_headers(self, &transfer, IO_HT_FROM | IO_HT_PATH);
		err = io_script_exit(data->child, true);
	}
	if (err > 0)
		err = -EFAULT;
	free(transfer.path);
	return err;
}

static int io_script_delete(struct io_handler *self, struct io_transfer_data *transfer)
{
	struct io_script_data *data = self->private_data;
	int err = io_script_prepare_cmd(self, transfer, "delete");

	if (!err) {
		io_script_write_headers(self, transfer, IO_HT_FROM | IO_HT_NAME | IO_HT_PATH);
		err = io_script_exit(data->child, true);
	}
	if (err > 0)
		err = -EFAULT;
	return err;
}

static struct io_handler* io_script_copy(struct io_handler *self)
{
	struct io_script_data *data = self->private_data;

	return io_script_init(data->script);
}

static struct io_handler_ops io_script_ops = {
	.open = io_script_open,
	.close = io_script_close,
	.delete = io_script_delete,
	.copy = io_script_copy,
	.cleanup = io_script_cleanup,
	.read = io_script_read,
	.write = io_script_write,
	.create_dir = io_script_create_dir,
};

struct io_handler * io_script_init(const char* script) {
	struct io_handler *handle = malloc(sizeof(*handle));
	struct io_script_data *data;

	if (!handle)
		return NULL;

	data = malloc(sizeof(*data));
	if (!data) {
		free(handle);
		return NULL;
	}

	memset(handle, 0, sizeof(*handle));
	handle->ops = &io_script_ops;
	handle->private_data = data;

	memset(data, 0, sizeof(*data));
	data->child = (pid_t)-1;
	data->script = script;

	return handle;
}
