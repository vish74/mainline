/* Copyright (C) 2006 Hendrik Sattler <post@hendrik-sattler.de>
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
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "obexpush-sdp.h"
#include "obex_auth.h"
#include "utf.h"
#include "md5.h"
#include <openobex/obex.h>

#define PROGRAM_NAME "obexpushd"
#include "version.h"

#if __GNUC__ >= 3
#define __noreturn __attribute__((noreturn))
#define __unused   /*@unused@*/ __attribute__((unused))
#else
#define __noreturn
#define __unused /*@unused@*/
#endif


char* obex_events[] = {
	"PROGRESS", "REQHINT", "REQ", "REQDONE",
	"LINERR", "PARSEERR", "ACCEPTHINT", "ABORT",
	"STREAMEMPTY", "STREAMAVAIL", "UNEXPECTED", "REQCHECK",
};

char* obex_commands[] = {
	"CONNECT", "DISCONNECT", "PUT", "GET",
	"SETPATH", "SESSION", "ABORT", "FINAL",
};


/* private data for a client connection */
struct file_data_t {
	unsigned int id;
	unsigned int count;

	uint16_t* name;
	char* type;
	size_t length;
	time_t time;

	FILE* out;

	/* auth */
	uint8_t nonce[16];
	int auth_success;
};

/* global settings */
static int debug = 0;
static int id = 0;
static /*@null@*/ char* auth_file = NULL;
static /*@null@*/ char* realm_file = NULL;
static /*@null@*/ char* script = NULL;

#define RANDOM_FILE "/dev/urandom"
int get_nonce (/*@out@*/ uint8_t nonce[16]) {
	int fd = open(RANDOM_FILE,O_RDONLY);
	uint8_t n[16];
	int status;
	if (fd < 0)
		return -errno;
	status = (int)read(fd,n,sizeof(n));
	if (status < 0)
		return -errno;
	if (status == 0)
		return -EIO;
	MD5(nonce,n,(size_t)status);
	(void)close(fd);
	return 0;
}

#define EOL(n) ((n) == '\n' || (n) == '\r')

/* return len(> 0), 0 if not found, or err codes(< 0) */
ssize_t get_pass_for_user (char* file,
			   uint8_t* user, size_t ulen,
			   /*@out@*/ uint8_t* pass, size_t size)
{
	ssize_t ret = 0;
	size_t lsize = ulen+1+size+3;
	char* line = malloc(lsize);
	FILE* f;
	
	if (!line)
		return -ENOMEM;
	f = fopen(file,"r");
	if (!f) {
		ret = (ssize_t)-errno;
		free(line);
		return ret;
	}
	while (1) {
		size_t len = 0;
		if (fgets(line,(int)lsize,f) == NULL)
			break;
		len = strlen(line);

		/* test that we read a whole line */
		if (!EOL(line[len])) {
			ret = -EINVAL; /* password in file too large */
			break;
		}

		if (line[len] == '\n')
			--len;
		if (line[len] == '\r')
			--len;

		if (ulen > len ||
		    memcmp(line,user,ulen) != 0 ||
		    line[ulen] != ':')
			continue;
		/* since the above matches the user id and the delimiter
		 * the rest of the line must be the password
		 */
		ret = (ssize_t)(len-ulen-1);
		if ((size_t)ret > size) {
			ret = -EINVAL; /* password in file too large */
			break;
		}
		memcpy(pass,line+ulen+1,(size_t)ret);
	}

	(void)fclose(f);
	free(line);
	return ret;
}

int obex_auth_verify_response (obex_t* handle,
			       obex_headerdata_t h,
			       uint32_t size)
{
	struct file_data_t* data = OBEX_GetUserData(handle);
	uint8_t d[16];
	uint8_t n[16];
	uint8_t u[20];
	int len = 0;
	uint8_t pass[1024];

	if (!auth_file)
		return 0;

	memset(d,0,sizeof(d));
	memset(u,0,sizeof(u));
	memcpy(n,data->nonce,sizeof(n));
	memset(pass,0,sizeof(pass));

	len = obex_auth_unpack_response(h,size,d,n,u);
	if (len < 0)
		return 0;
	len = (int)get_pass_for_user(auth_file,u,(size_t)len,pass,sizeof(pass));
	if (len < 0)
		return 0;
	return obex_auth_check_response(d,n,pass,(size_t)len);
}

/* return len(> 0), 0 if not found, or err codes(< 0) */
ssize_t get_credentials_for_realm (char* file,
				   uint16_t* realm,
				   /*@out@*/ uint8_t* user, size_t* usize,
				   /*@out@*/ uint8_t* pass, size_t* psize)
{
	ssize_t ret = 0;
	size_t size = *usize+1+*psize+1;
	uint8_t* buffer = malloc(size);
	uint8_t* r;
	
	if (!buffer)
		return -ENOMEM;
	r = utf16to8(realm);
	/* the format for both files is basicly the same */
	ret = get_pass_for_user(file,r,utf8len(r),buffer,size);
	free(r);
	r = NULL;
	if (ret > 0) {
		r = (uint8_t*)strchr((char*)buffer,(int)':');
		if (r == NULL ||
		    (usize != 0 && (size_t)(r-buffer) > *usize) ||
		    (size_t)((buffer+ret)-(r+1)) > *psize) {
			free(buffer);
			return -EINVAL;
		}
		if (usize) {
			*usize = (size_t)(r-buffer);
			if (user)
				memcpy(user,buffer,*usize);
		}

		*psize = (size_t)((buffer+ret)-(r+1));
		memcpy(pass,r+1,*psize);
	}
	free(buffer);
	return ret;
}

int obex_auth_send_response (obex_t* handle,
			     obex_object_t* obj,
			     obex_headerdata_t h,
			     uint32_t size)
{
	uint16_t realm[128];
	uint8_t user[20];
	uint8_t pass[128];
	uint8_t nonce[16];
	size_t usize = sizeof(user);
	size_t psize = sizeof(pass);
	uint8_t opts;
	ssize_t len;
	
	if (!realm_file)
		return -EINVAL;
	len = (ssize_t)obex_auth_unpack_challenge(h,size,nonce,&opts,realm,sizeof(realm));
	if (len < 0)
		return -EINVAL;
	if (get_credentials_for_realm(realm_file,realm,user,&usize,pass,&psize) > 0) {
		if ((opts & OBEX_AUTH_OPT_USER_REQ) != 0)
			return obex_auth_add_response(handle,obj,nonce,
						      user,sizeof(user)-1,
						      pass,sizeof(pass)-1);
		else
			return obex_auth_add_response(handle,obj,nonce,
						      NULL,0,
						      pass,sizeof(pass)-1);
	}
	return 0;
}

static
int create_file (struct file_data_t* data, int mode) {
	int fd;
	int err = 0;
	uint8_t* n = utf16to8(data->name);

	if (n) {
		printf("%u.%u: Creating file \"%s\"\n",data->id,data->count,(char*)n);
		fd = open((char*)n,mode|O_CREAT|O_EXCL,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		if (fd < 0)
			err = errno;
		free(n);
		return (fd < 0)? -err: fd;
	} else {
		return -EINVAL;
	}
}

int put_close (obex_t* handle) {
	struct file_data_t* data = OBEX_GetUserData(handle);
	if (script) {
		if (data->out) {
			if (pclose(data->out) < 0)
				return -errno;
			data->out = NULL;
		}
	} else {
		if (data->out) {
			if (fclose(data->out) == EOF)
				return -errno;
			data->out = NULL;
		}
	}
	return 0;
}

static
int put_open_pipe (struct file_data_t* data) {
	int err = 0;
	uint8_t* name = utf16to8(data->name);
	char* type = (type? strdup(data->type): NULL);
	char* cmd;
	
	if (name) {
		size_t i;
		size_t size = strlen(script)+1;
		size += 3+utf8len(name);
		if (type)
			size += 3+strlen(type);
		cmd = malloc(size);
		if (!cmd) {
			free(name);
			free(type);
			return -ENOMEM;
		}
		memset(cmd,0,size);
		
		/* clean name and type against attacks:
		 * replace ' with _
		 */
		for (i=0; i < utf8len(name); ++i)
			if (name[i] == '\'')
				name[i] = '_';
		if (type == NULL) {
			(void)snprintf(cmd, size, "%s '%s'", script, (char*)name);
		} else {
			for (i=0; i < strlen(type); ++i)
				if (type[i] == '\'')
					type[i] = '_';			
			(void)snprintf(cmd, size, "%s '%s' '%s'", script, (char*)name,type);
		}
	} else {
		cmd = strdup(script);
	}

	errno = 0;
	data->out = popen(cmd,"w");
	if (!data->out)
		err = (errno? -errno: -ENOMEM);
	free(cmd);
	free(name);
	free(type);
	return err;
}

int put_open_file (struct file_data_t* data) {
	int status = create_file(data,O_WRONLY);
	
	if (status >= 0) {
		data->out = fdopen(status,"w");
		if (!data->out)
			status = -errno;
	}
	if (status < 0) {
		fprintf(stderr,"%u.%u: Error: cannot create file: %s\n",data->id,data->count,strerror(-status));
		data->out = NULL;
		return status;
	}		
	return 0;
}

int put_open (obex_t* handle) {
	int err = 0;
	struct file_data_t* data = OBEX_GetUserData(handle);
	
	if (data->out)
		err = put_close(handle);
	if (err < 0)
		return err;

	if (script != NULL && strlen(script) > 0)
		return put_open_pipe(data);
	else
		return put_open_file(data);
}

int put_write (obex_t* handle, const uint8_t* buf, int len) {
	struct file_data_t* data = OBEX_GetUserData(handle);
	int err;

	if (!buf)
		return -EINVAL;
	(void)fwrite(buf,(size_t)len,1,data->out);
	err = ferror(data->out);
	if (err)
		return -err;
	if (debug) printf("%u.%u: wrote %d bytes\n",data->id,data->count,len);
	return 0;
}

void obex_object_headers (obex_t* handle, obex_object_t* obj) {
	uint8_t id = 0;
	obex_headerdata_t value;
	uint32_t vsize;
	struct file_data_t* data = OBEX_GetUserData(handle);

	while (OBEX_ObjectGetNextHeader(handle,obj,&id,&value,&vsize)) {
		if (debug)
			printf("%u.%u: Got header 0x%02x with value length %u\n",
			       data->id,data->count,(unsigned int)id,(unsigned int)vsize);
		if (!vsize)
			continue;
		switch (id) {
		case OBEX_HDR_NAME:
			if (data) {
				uint8_t* name;
				if (data->name)
					free(data->name);
				data->name = malloc(vsize+2);
				if (!data->name)
					return;
				memset(data->name,0,vsize+2);
				memcpy(data->name,value.bs,vsize);
				ucs2_ntoh(data->name,vsize/2);
				name = utf16to8(data->name);

				if (debug) printf("%u.%u: name: \"%s\"\n",data->id,data->count,(char*)name);
				if (strchr((char*)name,(int)':') ||
				    strchr((char*)name,(int)'\\') ||
				    strchr((char*)name,(int)'/'))
					(void)OBEX_ObjectSetRsp(obj,
								OBEX_RSP_BAD_REQUEST,
								OBEX_RSP_BAD_REQUEST);
				free(name);
			}
			break;

		case OBEX_HDR_TYPE:
			if (data) {
				if (data->type)
					free(data->type);
				data->type = malloc(vsize+1);
				if (!data->type)
					return;
				memcpy(data->type,value.bs,vsize);
				data->type[vsize] = '\0';
			}
			if (debug) printf("%u.%u: type: \"%s\"\n",data->id,data->count,data->type);
			break;

		case OBEX_HDR_LENGTH:
			if (data)
				data->length = value.bq4;
			if (debug) printf("%u.%u: size: %d bytes\n",data->id,data->count,value.bq4);
			break;

		case OBEX_HDR_TIME:
			//TODO
			break;

		case OBEX_HDR_DESCRIPTION:
			if (debug) {
				uint16_t* desc16 = (uint16_t*)value.bs;
				if (desc16[vsize/2] == 0x0000) {
					uint8_t* desc8 = utf16to8(desc16);
					printf("%u.%u: description: \"%s\"\n",data->id,data->count,(char*)desc8);
					free(desc8);
				}
			}
			break;

		case OBEX_HDR_AUTHCHAL:
			if (realm_file && data->auth_success)
				(void)obex_auth_send_response(handle,obj,value,vsize);
			break;

		case OBEX_HDR_AUTHRESP:
			data->auth_success = obex_auth_verify_response(handle,value,vsize);
			break;

		default:
			/* some unexpected header, may be a bug */
			return;
		}
	}
}

void obex_action_connect (obex_t* handle, obex_object_t* obj, int event) {
	struct file_data_t* data = OBEX_GetUserData(handle);
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		if (auth_file && !data->auth_success) {
			uint8_t nonce[16];
			if (get_nonce(nonce) < 0)
				(void)OBEX_ObjectSetRsp(obj,
							OBEX_RSP_SERVICE_UNAVAILABLE,
							OBEX_RSP_SERVICE_UNAVAILABLE);
			memcpy(data->nonce,nonce,sizeof(data->nonce));
			(void)obex_auth_add_challenge(handle,obj,
						      nonce,
						      (uint8_t)(OBEX_AUTH_OPT_USER_REQ|OBEX_AUTH_OPT_FULL_ACC),
						      NULL);
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_UNAUTHORIZED,
						OBEX_RSP_UNAUTHORIZED);
		} else
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_CONTINUE,
						OBEX_RSP_SUCCESS);
		
		break;
	}
}

void obex_action_disconnect (obex_t* handle, obex_object_t* obj, int event) {
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
		break;

	case OBEX_EV_REQDONE:
		(void)OBEX_TransportDisconnect(handle);
		break;
	}
}

void obex_action_put (obex_t* handle, obex_object_t* obj, int event) {
	struct file_data_t* data = OBEX_GetUserData(handle);
	const uint8_t* buf = NULL;
	int len = 0;

	obex_object_headers(handle,obj);
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
		(void)OBEX_ObjectReadStream(handle,obj,NULL);
		data->count += 1;
		data->length = 0;
		data->time = 0;
		break;

	case OBEX_EV_REQCHECK:
		if (put_open(handle) < 0)
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_FORBIDDEN,
						OBEX_RSP_FORBIDDEN);
		break;

	case OBEX_EV_STREAMAVAIL:
		len = OBEX_ObjectReadStream(handle,obj,&buf);

		if (debug) printf("%u.%u: got %d bytes of streamed data\n",data->id,data->count,len);
		if (len)
			if (put_write(handle,buf,len))
				(void)OBEX_ObjectSetRsp(obj,
							OBEX_RSP_FORBIDDEN,
							OBEX_RSP_FORBIDDEN);
		break;

	case OBEX_EV_REQDONE:
		(void)put_close(handle);
		break;
	}
}

void obex_action_get (obex_t* handle, obex_object_t* obj, int event) {
	obex_object_headers(handle,obj);
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		/* There is no default object to get */
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_NOT_FOUND,
					OBEX_RSP_NOT_FOUND);
		break;

	case OBEX_EV_REQ: /* An incoming request */
		/* If there is a default object but the name header
		 * is non-empty:
		 */
		/* if (data->name) */
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_FORBIDDEN,
					OBEX_RSP_FORBIDDEN);
		//TODO
		break;
	}
}

void client_eventcb (obex_t* handle, obex_object_t* obj,
		     int __unused mode, int event,
		     int obex_cmd, int __unused obex_rsp)
{
	struct file_data_t* data = OBEX_GetUserData(handle);
	static int last_obex_cmd = 0;

	/* work-around for openobex bug */
	if (event == OBEX_EV_STREAMAVAIL)
		obex_cmd = last_obex_cmd;
	else
		last_obex_cmd = obex_cmd;

	if (debug) printf("%u: OBEX_EV_%s, OBEX_CMD_%s\n",data->id,
			  obex_events[event],
			  obex_commands[obex_cmd]);
	switch (obex_cmd) {
	case OBEX_CMD_CONNECT:
		obex_action_connect(handle,obj,event);
		break;

	case OBEX_CMD_PUT:
		if (!auth_file || data->auth_success)
			obex_action_put(handle,obj,event);
		break;

	case OBEX_CMD_GET:
		if (!auth_file || data->auth_success)
			obex_action_get(handle,obj,event);
		break;

	case OBEX_CMD_DISCONNECT:
		obex_action_disconnect(handle,obj,event);
		break;

	default:
		switch (event) {
		case OBEX_EV_REQHINT: /* A new request is coming in */
			/* Reject any other commands */                       
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_NOT_IMPLEMENTED,
						OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
	}
}

void handle_client (obex_t* client) {
	int status = 0;
	struct file_data_t* data = malloc(sizeof(*data));

	if (!client)
		exit(EXIT_FAILURE);
	if (data) memset(data,0,sizeof(*data));
	data->id = id++;

	OBEX_SetUserData(client,data);
	while (status != -1) {
		status = OBEX_HandleInput(client,10);
	}

	if (data) {
		if (data->name) free(data->name);
		if (data->type) free(data->type);
		free(data);
	}
	OBEX_Cleanup(client);
	exit(EXIT_SUCCESS);
}

void eventcb (obex_t* handle, obex_object_t __unused *obj,
	      int __unused mode, int event,
	      int __unused obex_cmd, int __unused obex_rsp)
{
	if (debug) printf("OBEX_EV_%s, OBEX_CMD_%s\n",
			  obex_events[event],
			  obex_commands[obex_cmd]);
	if (obj) obex_object_headers(handle,obj);
	switch (event) {
	case OBEX_EV_ACCEPTHINT:
	{
		obex_t* client = OBEX_ServerAccept(handle,client_eventcb,NULL);
		if (client && fork() == 0)
			handle_client(client);
	}
	break;
	}
}

/*@null@*/
obex_t* irda_listen (char* service) {
	obex_t* handle = OBEX_Init(OBEX_TRANS_IRDA,eventcb,OBEX_FL_KEEPSERVER);
	
	if (handle) {
		(void)IrOBEX_ServerRegister(handle,service);
		fprintf(stderr,"Listening on IrDA service \"%s\"\n", service);
	}
	return handle;
}

/*@null@*/
obex_t* bluetooth_listen (uint8_t* channel) {
	obex_t* handle = OBEX_Init(OBEX_TRANS_BLUETOOTH,eventcb,OBEX_FL_KEEPSERVER);
  
	if (handle) {
		if (BtOBEX_ServerRegister(handle,BDADDR_ANY,*channel)) {
			sdp_session_t* session = bt_sdp_session_open(*channel);
			fprintf(stderr,"Listening on bluetooth channel %u\n",(unsigned int)*channel);
			if (!session) {
				OBEX_Cleanup(handle);
				handle = NULL;
			}
		}
	}
	return handle;
}

void print_disclaimer () {
	printf(PROGRAM_NAME " " OBEXPUSHD_VERSION " Copyright (C) 2006 Hendrik Sattler\n"
	       "This software comes with ABSOLUTELY NO WARRANTY.\n"
	       "This is free software, and you are welcome to redistribute it\n"
	       "under certain conditions.\n");
}

void print_help (char* me) {
	print_disclaimer();
	printf("\n");
	printf("Usage: %s [<interfaces>] [<options>]\n", me);
	printf("\n"
	       "Interfaces:\n"
	       " -B[<channel>]  listen to bluetooth connections (default with channel 9)\n"
	       " -I[<app>]      listen to IrDA connections (app example: IrXfer)\n"
	       "\n"
	       "Options:\n"
	       " -n             do not detach from terminal\n"
	       " -d             enable debug messages\n"
	       " -p <file>      write pid to file when getting detached\n"
	       " -a <file>      authenticate against credentials from file (EXPERIMENTAL)\n"
	       " -r <file>      use realm credentials from file (EXPERIMENTAL)\n"
	       " -s <file>      run script or program file and pipe incoming data to it\n"
	       " -h             this help message\n"
	       " -v             show version\n");
}

#define INTF_BLUETOOTH (1 << 0)
#define INTF_IRDA      (1 << 1)
int main (int argc, char** argv) {
	int retval = EXIT_SUCCESS;
	int c;
	int n = 1;
	int intf = 0;
	uint8_t btchan = 9;
	char* irda_extra = NULL;
	char* pidfile = NULL;
	
	obex_t* handle[3] = { NULL, NULL, NULL };
#define BT_HANDLE         handle[0]
#define IRDA_HANDLE       handle[1]
#define IRDA_EXTRA_HANDLE handle[2]  
	int topfd = 0;
	
	while ((c = getopt(argc,argv,"B::I::a:dhnp:r:s:v")) != -1) {
		switch (c) {
		case 'B':
			intf |= INTF_BLUETOOTH;
			if (optarg) {
				int arg = atoi(optarg);
				if (arg < 0x00 || arg > 0xFF) {
					fprintf(stderr,"Error: %s\n", "bluetooth channel value out of range.");
					exit(EXIT_FAILURE);
				}
				btchan = (uint8_t)arg;
			}
			break;

		case 'I':
			intf |= INTF_IRDA;
			irda_extra = optarg;
			break;

		case 'd':
			debug = 1;
			/* no break */

		case 'n':
			n = 0;
			break;

		case 'p':
			pidfile = optarg;
			break;

		case 'a':
			auth_file = optarg;
			break;

		case 'r':
			realm_file = optarg;
			break;

		case 's':
			script = optarg;
			break;

		case 'h':
			print_help(PROGRAM_NAME);
			exit(EXIT_SUCCESS);

		case 'v':
			printf("%s\n",OBEXPUSHD_VERSION);
			exit(EXIT_SUCCESS);
		}
	}
	if (intf == 0) intf |= INTF_BLUETOOTH;
	
	if (n) {
		if (daemon(1,0) < 0) {
			perror("daemon()");
			exit(EXIT_FAILURE);
		}
		if (pidfile) {
			FILE* p = fopen(pidfile,"w+");
			if (p) {
				fprintf(p,"%u\n",(unsigned int)getpid());
				(void)fclose(p);
			}
		}
	} else {
		print_disclaimer();
	}
	
	if (intf & INTF_BLUETOOTH) {
		int fd = -1;
		BT_HANDLE = bluetooth_listen(&btchan);
		if (BT_HANDLE)
			fd = OBEX_GetFD(BT_HANDLE);
		if (fd == -1) {
			perror("OBEX_GetFD(BT_HANDLE)");
			exit(EXIT_FAILURE);
		}
		if (fd > topfd)
			topfd = fd;
	}
	if (intf & INTF_IRDA) {
		int fd = -1;
		IRDA_HANDLE = irda_listen("OBEX");
		if (IRDA_HANDLE)
			fd = OBEX_GetFD(IRDA_HANDLE);
		if (fd == -1) {
			perror("OBEX_GetFD(IRDA_HANDLE)");
			exit(EXIT_FAILURE);
		}
		if (fd > topfd)
			topfd = fd;
		if (irda_extra) {
			size_t slen = 5+strlen(irda_extra)+1;
			char* service = malloc(slen);
			if (service) {
				fd = -1;
				(void)snprintf(service,slen,"OBEX:%s",irda_extra);
				IRDA_EXTRA_HANDLE = irda_listen(service);
				if (IRDA_EXTRA_HANDLE)
					fd = OBEX_GetFD(IRDA_EXTRA_HANDLE);
				if (fd == -1) {
					perror("OBEX_GetFD(IRDA_EXTRA_HANDLE)");
					exit(EXIT_FAILURE);
				}
				if (fd > topfd)
					topfd = fd;
				free(service);
			}
		}
	}
	++topfd;
	
	(void)signal(SIGCLD, SIG_IGN);
	do {
		int fd = -1;
		fd_set fds;
		FD_ZERO(&fds);
		if (intf & INTF_BLUETOOTH)
			FD_SET(OBEX_GetFD(BT_HANDLE),&fds);
		if (intf & INTF_IRDA) {
			FD_SET(OBEX_GetFD(IRDA_HANDLE),&fds);
			if (irda_extra)
				FD_SET(OBEX_GetFD(IRDA_EXTRA_HANDLE),&fds);
		}
		select(topfd,&fds,NULL,NULL,NULL);
		if (intf & INTF_BLUETOOTH) {
			fd = OBEX_GetFD(BT_HANDLE);
			if (FD_ISSET(fd,&fds))
				(void)OBEX_HandleInput(BT_HANDLE,1);
		}
		if (intf & INTF_IRDA) {
			fd = OBEX_GetFD(IRDA_HANDLE);
			if (FD_ISSET(fd,&fds))
				(void)OBEX_HandleInput(IRDA_HANDLE,1);
			if (irda_extra) {
				fd = OBEX_GetFD(IRDA_EXTRA_HANDLE);
				if (FD_ISSET(fd,&fds))
					(void)OBEX_HandleInput(IRDA_EXTRA_HANDLE,1);	  
			}
		}
	} while (1);
	
	return retval;
}
