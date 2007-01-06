#define _GNU_SOURCE
#include "obexpushd.h"
#include "utf.h"
#include "data_io.h"

#include <openobex/obex.h>

#include <stdio.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>

#define EOL(n) ((n) == '\n' || (n) == '\r')

static
int get_parse_headers (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	char buffer[512+1];

	while (1) {
		size_t len = 0;
		size_t status = fread(buffer,1,sizeof(buffer),data->out);
		if (status == 0)
			return -ferror(data->out);
		len = strlen(buffer);

		if (!EOL(buffer[len-1])) {
			while (!EOL(buffer[len-1])) {
				if (feof(data->out) > 0)
					return -EINVAL;
				status = fread(buffer,1,sizeof(buffer),data->out);
				if (status == 0)
					return -ferror(data->out);
			}
		}
		
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
			data->name = utf8to16((uint8_t*)(buffer+6));
		} else if (strncasecmp(buffer,"Length: ",8) == 0) {
			long len = strtol(buffer+8,NULL,10);
			if (len > (long)UINT32_MAX || len == LONG_MAX)
				return -ERANGE;
			data->length = (uint32_t)len;

		} else if (strncasecmp(buffer,"Type: ",6) == 0) {
			char* type = buffer+6;
			size_t len = strlen(type);
			size_t i = 0;
			size_t k = 0;
			for (; i < len; ++i) {
				if (type[i] == '/')
					++k;
				if (!isascii((int)type[i])
				    || isspace((int)type[i])
				    || iscntrl((int)type[i])
				    || k > 1)
					return -EINVAL;
			}
			data->type = strdup(type);
		} else
			continue;
	}
	return 0;
}

int get_close (obex_t* handle, int w) {
	file_data_t* data = OBEX_GetUserData(handle);
	if (data->out) {
		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;
	}
	if (w) {
		int status;
		(void)wait(&status);
	}
	return 0;
}

int get_open (obex_t* handle, char* script) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err = 0;
	uint8_t* name = utf16to8(data->name);
	char* args[5] = {
		script,
		"get",
		(name? (char*)name: ""),
		data->type,
		NULL
	};

	if (data->out) {
		int err = get_close(handle,(script != NULL));
		if (err < 0)
			return err;
	}

	err = pipe_open(script,args,O_WRONLY,&data->child);
	if (err >= 0) {
		data->out = fdopen(err,"w");
		if (data->out == NULL)
			err = -errno;
	}

	if (err == 0)
		err = get_parse_headers(handle);

	return err;
}

int get_read (obex_t* handle, uint8_t* buf, size_t size) {
	file_data_t* data = OBEX_GetUserData(handle);
	size_t status = fread(buf,1,size,data->out);
	
	if (status < size && !feof(data->out))		
		return -ferror(data->out);
	else
		return 0;
}
