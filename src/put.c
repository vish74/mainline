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
#include "data_io.h"
#include "utf.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

int put_close (obex_t* handle, int w) {
	file_data_t* data = OBEX_GetUserData(handle);
	if (data->out) {
		if (fclose(data->out) == EOF)
			return -errno;
		data->out = NULL;
	}
	if (w) {
		(void)waitpid(data->child,NULL,0);
		data->child = 0;
	}
	return 0;
}

static
int put_open_pipe (file_data_t* data, char* script) {
	int err = 0;
	int p = 0;
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

	p = pipe_open(script,args,O_WRONLY,&data->child);
	if (p >= 0) {
		data->out = fdopen(p,"w");
		if (data->out == NULL)
			err = -errno;
	}
	free(name);

	/* headers can be written here */
	fprintf(data->out,"Name: %s\r\n",name);
	fprintf(data->out,"Length: %u\r\n",data->length);
	if (data->type)
		fprintf(data->out,"Type: %s\r\n",data->type);
	
	/* empty line signals that data follows */
	(void)fprintf(data->out,"\r\n");

	return (err? err: p);
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

int put_revert (obex_t* handle) {
	file_data_t* data = OBEX_GetUserData(handle);
	if (data->out) {
		if (data->child >= 0) {
			if (!data->child)
				return -ECHILD;
			kill(data->child,SIGTERM); /* tell it to clean up */
			sleep(3);
			kill(data->child,SIGKILL); /* kill it */
			return put_close(handle,1); /* clean up our side */
		} else {
			uint8_t* n = utf16to8(data->name);		
			if (unlink((char*)n) == -1) /* remove the file */
				return -errno;
			return put_close(handle,0);
		}
	}
	return 0;
}
