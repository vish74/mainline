
#define _GNU_SOURCE

#include "obexpushd.h"
#include "data_io.h"
#include "utf.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int put_close (obex_t* handle, int w) {
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

static
int put_open_pipe (file_data_t* data, char* script) {
	int err = 0;
	uint8_t* name = utf16to8(data->name);
	char* args[5] = {
		script,
		"put",
		(char*)name,
		data->type,
		NULL
	};

	if (!name)
		return -EINVAL;

	err = pipe_open(script,args,O_WRONLY);
	if (err >= 0) {
		data->out = fdopen(err,"w");
		if (data->out == NULL)
			err = -errno;
	}
	free(name);
	/* headers can be written here */
	/* empty line signals that data follows */
	(void)write(err,"\n",1);
	return err;
}

static
int put_open_file (file_data_t* data) {
	uint8_t* n = utf16to8(data->name);
	int status;

	if (!n)
		return -EINVAL;
	printf("%u.%u: Creating file \"%s\"\n",data->id,data->count,(char*)n);
	status = file_open((char*)n,O_WRONLY);
	
	if (status >= 0) {
		data->out = fdopen(status,"w");
		if (data->out == NULL)
			status = -errno;
	}
	free(n);
	if (status < 0) {
		fprintf(stderr,"%u.%u: Error: cannot create file: %s\n",data->id,data->count,strerror(-status));
		data->out = NULL;
		return status;
	}		
	return 0;
}

int put_open (obex_t* handle, char* script) {
	file_data_t* data = OBEX_GetUserData(handle);
	
	if (data->out) {
		int err = put_close(handle,(script != NULL));
		if (err < 0)
			return err;
	}
	if (script != NULL && strlen(script) > 0)
		return put_open_pipe(data,script);
	else
		return put_open_file(data);
}

int put_write (obex_t* handle, const uint8_t* buf, int len) {
	file_data_t* data = OBEX_GetUserData(handle);
	int err;

	if (!buf)
		return -EINVAL;
	(void)fwrite(buf,(size_t)len,1,data->out);
	err = ferror(data->out);
	if (err)
		return -err;
	return 0;
}
