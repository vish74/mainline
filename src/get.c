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

#define _GNU_SOURCE

#include "obexpushd.h"
#include "utf.h"
#include "data_io.h"
#include "net.h"

#include <openobex/obex.h>

#include <stdio.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>

#define EOL(n) ((n) == '\n' || (n) == '\r')

static
int get_parse_headers (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	char buffer[512+1];

	while (1) {
		size_t len = 0;
		if (fgets(buffer,sizeof(buffer),data->out) == NULL) {
			if (!feof(data->out))
				return -ferror(data->out);
			else
				return -EINVAL;
		}
		len = strlen(buffer);

		if (!EOL(buffer[len-1]) && feof(data->out))
			return -EINVAL;
		
		if (buffer[len-1] == '\n')
			--len;
		if (buffer[len-1] == '\r')
			--len;
		buffer[len] = 0;

		/* stop on the first empty line */
		if (len == 0)
			break;

		/* compare the first part of buffer with known headers
		 * and ignore unknown ones
		 */
		if (strncasecmp(buffer,"Name: ",6) == 0) {
			uint16_t* name = utf8to16((uint8_t*)(buffer+6));
			if (!check_name(name)) {
				free(name);
				return -EINVAL;
			}
			if (data->name)
				free(data->name);
			data->name = name;

		} else if (strncasecmp(buffer,"Length: ",8) == 0) {
			char* endptr;
			long dlen = strtol(buffer+8, &endptr, 10);
			if ((dlen == LONG_MIN || dlen == LONG_MAX) && errno == ERANGE)
				return -errno;

			if (endptr != 0 && (0 <= dlen && dlen <= UINT32_MAX)) {
				data->length = (uint32_t)dlen;
				continue;
			}

		} else if (strncasecmp(buffer,"Type: ",6) == 0) {
			char* type = buffer+6;
			if (!check_type(type))
				return -EINVAL;
			if (data->type)
				free(data->type);
			data->type = strdup(type);
		} else
			continue;
	}
	return 0;
}

int get_close (obex_t* handle, int w) {
	file_data_t* data = OBEX_GetUserData(handle);
	if (data->child < 0)
		return 0;

	kill(data->child, SIGKILL);
	if (data->out) {
		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;
	}
	if (w) {
		int status;
		if (waitpid(data->child, &status, 0) < 0)
			return -errno;

		if (WIFEXITED(status)) {
			fprintf(stderr, "%u.%u: script exited with exit code %d\n",
				data->id, data->count, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "%u.%u: script got signal %d\n",
				data->id, data->count, WTERMSIG(status));
		}
	}
	return 0;
}

int get_open (obex_t* handle, char* script) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err = 0;
	int p[2] = { -1, -1};
	char* args[5] = {
		script,
		"get",
		NULL
	};

	if (data->out) {
	        err = get_close(handle,(script != NULL));
		if (err < 0)
			return err;
	}

	data->child = pipe_open(script, args, p);
	if (p[0] >= 0) {
		data->out = fdopen(p[0], "r");
		if (data->out == NULL) {
			err = errno;
			pipe_close(p);
			return -err;
		}
	}

	if (p[1] >= 0) {
		char from[256];
		FILE* ctrl = fdopen(p[1], "w");
		uint8_t* name;

		if (ctrl == NULL) {
			err = errno;
			pipe_close(p);
			return -err;
		}

		memset(from, 0, sizeof(from));
		net_get_peer(data->net_data, from, sizeof(from));

		/* headers can be written here */
		fprintf(ctrl, "From: %s\n", (strlen(from)? from: "unknown"));
		name = utf16to8(data->name);
		if (strlen((char*)name))
			fprintf(ctrl, "Name: %s\n", name);
		free(name);
		if (data->type)
			fprintf(ctrl, "Type: %s\n", data->type);

		/* empty line signals that data follows */
		fprintf(ctrl, "\n");
		fflush(ctrl);

		close(p[1]);
	}

	if (err == 0)
		err = get_parse_headers(handle);

	return err;
}

int get_read (obex_t* handle, uint8_t* buf, size_t size) {
	file_data_t* data = OBEX_GetUserData(handle);
	size_t status;

	if (!data->out)
		return -EBADF;
	status = fread(buf, sizeof(*buf), size, data->out);
	
	if (status < size && !feof(data->out))		
		return -ferror(data->out);
	else
		return status;
}
