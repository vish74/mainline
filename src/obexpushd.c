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

#include "obex_auth.h"
#include "obexpushd.h"
#include "data_io.h"
#include "utf.h"
#include "net.h"

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
#include <ctype.h>

#if defined(USE_THREADS)
#include <pthread.h>
#endif

#define PROGRAM_NAME "obexpushd"
#include "version.h"
#include "compiler.h"

char* obex_events[] = {
	"PROGRESS", "REQHINT", "REQ", "REQDONE",
	"LINKERR", "PARSEERR", "ACCEPTHINT", "ABORT",
	"STREAMEMPTY", "STREAMAVAIL", "UNEXPECTED", "REQCHECK",
};

char* _obex_commands[] = {
	"CONNECT", "DISCONNECT", "PUT", "GET",
	"SETPATH", "SESSION", "ABORT"
};

/* global settings */
static int debug = 0;
static int nofork = 0;
static int id = 0;
static /*@null@*/ char* auth_file = NULL;
static /*@null@*/ char* realm_file = NULL;
static /*@null@*/ char* script = NULL;


#define EOL(n) ((n) == '\n' || (n) == '\r')

/* return len(> 0), 0 if not found, or err codes(< 0) */
ssize_t get_pass_for_user (char* file,
			   const uint8_t* user, size_t ulen,
			   /*@out@*/ uint8_t* pass, size_t size)
{
	ssize_t ret = 0;
	size_t lsize = ulen+1+size+3;
	char* line = malloc(lsize);
	int status = 0;
	FILE* f;
	
	if (!line)
		return -ENOMEM;
	if (file[0] == '|') {
		char* args[2] = { file+1, (char*)user };
		int fds[2];
		(void)pipe_open(args[0],args,fds);
		close(fds[1]);
		status = fds[0];
	} else {
		status = file_open(file,O_RDONLY);
	}
	if (status < 0) {
		free(line);
		return status;
	}
	f = fdopen(status,"r");
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
		if (!EOL(line[len-1])) {
			ret = -EINVAL; /* password in file too large */
			break;
		}

		if (line[len-1] == '\n')
			--len;
		if (line[len-1] == '\r')
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

int obex_auth_verify_response (obex_t __unused *handle,
			       obex_headerdata_t h,
			       uint32_t size)
{
	struct obex_auth_response resp;
	uint8_t pass[1024];
	int len;

	if (!auth_file)
		return 0;

	memset(&resp,0,sizeof(resp));
	memset(pass,0,sizeof(pass));

	if (obex_auth_unpack_response(h,size,&resp) < 0)
		return 0;
	len = (int)get_pass_for_user(auth_file,resp.user,resp.ulen,pass,sizeof(pass));
	if (len < 0)
		return 0;
	return obex_auth_check_response(&resp,pass,(size_t)len);
}

/* return len(> 0), 0 if not found, or err codes(< 0) */
ssize_t get_credentials_for_realm (char* file,
				   const uint8_t* realm,
				   /*@out@*/ uint8_t* user, size_t* usize,
				   /*@out@*/ uint8_t* pass, size_t* psize)
{
	ssize_t ret = 0;
	size_t size = *usize+1+*psize+1;
	uint8_t* buffer = malloc(size);
	uint8_t* r = NULL;
	
	if (!buffer)
		return -ENOMEM;
	/* the format for both files is basicly the same */
	ret = get_pass_for_user(file,realm,utf8len(r),buffer,size);

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

static
void get_creds (obex_t __unused *handle,
		const char* realm, /* UTF-8 */
		/*out*/ char* user,
		size_t* ulen,
		/*out*/ char* pass,
		size_t* plen)
{
	get_credentials_for_realm(realm_file,
				  (const uint8_t*)realm,
				  (uint8_t*)user,ulen,
				  (uint8_t*)pass,plen);
}

int obex_auth_send_response (obex_t* handle,
			     obex_object_t* obj,
			     obex_headerdata_t h,
			     uint32_t size)
{
	struct obex_auth_challenge chal;
	struct obex_auth_response resp;
	ssize_t len;
	
	if (!realm_file)
		return -EINVAL;
	memset(&chal,0,sizeof(chal));
	len = (ssize_t)obex_auth_unpack_challenge(h,size,&chal,1);
	if (len < 0)
		return -EINVAL;
	obex_auth_challenge2response(handle,&chal,&resp,get_creds);
	free(chal.realm);
	return obex_auth_add_response(handle,obj,&resp);
}

char* obex_command_string(uint8_t cmd)
{
	switch (cmd) {
	case OBEX_CMD_CONNECT:
	case OBEX_CMD_DISCONNECT:
	case OBEX_CMD_PUT:
	case OBEX_CMD_GET:
		return _obex_commands[cmd];
	case OBEX_CMD_SETPATH:
		return _obex_commands[4];
	case OBEX_CMD_SESSION:
		return _obex_commands[5];
	case OBEX_CMD_ABORT:
		return _obex_commands[6];
	default:
		return "UNKNOWN";
	}
}

int obex_object_headers (obex_t* handle, obex_object_t* obj) {
	uint8_t id = 0;
	obex_headerdata_t value;
	uint32_t vsize;
	file_data_t* data = OBEX_GetUserData(handle);

	while (OBEX_ObjectGetNextHeader(handle,obj,&id,&value,&vsize)) {
		if (debug)
			printf("%u.%u: Got header 0x%02x with value length %u\n",
			       data->id,data->count,(unsigned int)id,(unsigned int)vsize);
		if (!vsize)
			continue;
		switch (id) {
		case OBEX_HDR_NAME:
			if (data) {
				if (data->name)
					free(data->name);
				data->name = malloc(vsize+2);
				if (!data->name)
					return 0;
				memset(data->name,0,vsize+2);
				memcpy(data->name,value.bs,vsize);
				ucs2_ntoh(data->name,vsize/2);
				if (debug) {
					uint8_t* n = utf16to8(data->name);
					printf("%u.%u: name: \"%s\"\n",data->id,data->count,(char*)n);
					free(n);
				}
				if (!check_name(data->name)) {
					printf("%u.%u: CHECK FAILED: Invalid name string\n",data->id,data->count);
					return 0;
				}
			}
			break;

		case OBEX_HDR_TYPE:
			if (data) {
				if (data->type)
					free(data->type);
				data->type = malloc(vsize+1);
				if (!data->type)
					return 0;
				memcpy(data->type,value.bs,vsize);
				data->type[vsize] = '\0';
				if (debug)
					printf("%u.%u: type: \"%s\"\n",data->id,data->count,data->type);
				if (!check_type(data->type)) {
					printf("%u.%u: CHECK FAILED: Invalid type string\n",data->id,data->count);
					return 0;
				}
			}
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
			if (realm_file && data->net_data->auth_success)
				(void)obex_auth_send_response(handle,obj,value,vsize);
			break;

		case OBEX_HDR_AUTHRESP:
			data->net_data->auth_success = obex_auth_verify_response(handle,value,vsize);
			break;

		default:
			/* some unexpected header, may be a bug */
			break;
		}
	}
	return 1;
}

static
void obex_send_response (obex_t* handle, obex_object_t* obj, uint8_t respCode) {
	switch (respCode) {
	case OBEX_RSP_CONTINUE:
	case OBEX_RSP_SUCCESS:
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
		break;

	default:
	        {
			file_data_t* data = OBEX_GetUserData(handle);
			(void)OBEX_ObjectSetRsp(obj, respCode, respCode);
			data->error = respCode;
			break;
		}
	}
}

void obex_action_connect (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	uint8_t code = OBEX_RSP_CONTINUE;
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		if (auth_file && !data->net_data->auth_success)
			code = net_security_init(data->net_data, obj);
		obex_send_response(handle, obj, code);
		break;
	}
}

void obex_action_disconnect (obex_t* handle, obex_object_t* obj, int event) {
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		obex_send_response(handle, obj, OBEX_RSP_CONTINUE);
		break;

	case OBEX_EV_REQDONE:
		(void)OBEX_TransportDisconnect(handle);
		break;
	}
}

void obex_action_put (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);

	if (data->error &&
	    (event == OBEX_EV_REQ ||
	     event == OBEX_EV_REQCHECK ||
	     event == OBEX_EV_STREAMAVAIL))
	{
		obex_send_response(handle, obj, data->error);
		return;
	}
	if (!obex_object_headers(handle,obj)) {
		obex_send_response(handle, obj, OBEX_RSP_BAD_REQUEST);
		return;
	}
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		(void)OBEX_ObjectReadStream(handle,obj,NULL);
		data->error = 0;
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		if (data->type) {
			free(data->type);
			data->type = NULL;
		}
		data->count += 1;
		data->length = 0;
		data->time = 0;
		data->out = NULL;
		break;

	case OBEX_EV_REQCHECK:
		if (data->out == NULL
		    && put_open(handle,script) < 0)
			obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
		else
			obex_send_response(handle, obj, OBEX_RSP_CONTINUE);
		break;

	case OBEX_EV_STREAMAVAIL:
	{
		const uint8_t* buf = NULL;
		int len = OBEX_ObjectReadStream(handle,obj,&buf);

		if (debug) printf("%u.%u: got %d bytes of streamed data\n",data->id,data->count,len);
		if (len) {
			if ((data->out == NULL
			     && put_open(handle,script) < 0)
			    || put_write(handle,buf,len))
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
		}
		break;
	}

	case OBEX_EV_REQDONE:
		(void)put_close(handle,(script != NULL));
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		if (data->type) {
			free(data->type);
			data->type = NULL;
		}
		data->length = 0;
		data->time = 0;
		break;

	case OBEX_EV_ABORT:
		(void)put_revert(handle);
		break;
	}
}

void obex_action_get (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	int len = 0;

	if (data->error &&
	    (event == OBEX_EV_REQ ||
	     event == OBEX_EV_REQCHECK ||
	     event == OBEX_EV_STREAMEMPTY))
	{
		obex_send_response(handle, obj, data->error);
		return;
	}
	if (!obex_object_headers(handle,obj)) {
		obex_send_response(handle, obj, OBEX_RSP_BAD_REQUEST);
		return;
	}
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		data->error = 0;
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		/* in case that there is no TYPE header */
		data->type = strdup("text/x-vcard");
		data->count += 1;
		data->length = 0;
		data->time = 0;
		if (!script) {
			/* There is no default object to get */
			fprintf(stderr, "No script defined\n");
			obex_send_response(handle, obj, OBEX_RSP_NOT_FOUND);
			break;
		}
		break;

	case OBEX_EV_REQ:
	{
		obex_headerdata_t hv;
		
		if (data->out == NULL) {
			/* If there is a default object but the name header
			 * is non-empty. Special case is that
			 * type == x-obex/object-profile, then name contains the
			 * real type
			 */
			/* TODO: allowing x-obex/folder-listing would essentially implement
			 * obexftp. However, this requires the FBS-UUID and secure directory
			 * traversal. That's not implemented, yet.
			 */
			if ((strcmp(data->type,"x-obex/object-profile") != 0 && data->name)
			    || strcmp(data->type,"x-obex/folder-listing") == 0)
			{
				printf("%u.%u: %s\n", data->id, data->count,
				       "Forbidden request");
				obex_send_response(handle, obj, OBEX_RSP_FORBIDDEN);
			}

			if (get_open(handle,script) < 0 ||
			    data->length == 0)
			{
				data->out = NULL;
				printf("%u.%u: %s\n", data->id, data->count,
				       "Running script failed or no output data");
				obex_send_response(handle, obj, OBEX_RSP_INTERNAL_SERVER_ERROR);
			}
			if (event == OBEX_EV_REQCHECK)
				break;
		}

		obex_send_response(handle, obj, OBEX_RSP_CONTINUE);
		if (data->name) {
			size_t size = utf16len(data->name);
			if (size) {
				size += 2;
				hv.bs = malloc(size);
				if (hv.bs) {
					memcpy((char*)hv.bs,data->name,size);
					ucs2_hton((uint16_t*)hv.bs,size);
					(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_NAME,
								   hv,size,0);
					free((uint8_t*)hv.bs);
				}
			}
		}
		hv.bs = (const uint8_t*)data->type;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_TYPE,
					   hv,strlen((char*)hv.bs),0);
		hv.bq4 = data->length;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_LENGTH,
					   hv,sizeof(hv.bq4),0);
		hv.bs = NULL;
		(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
					   hv,0,
					   OBEX_FL_STREAM_START);
	}
		break;

	case OBEX_EV_STREAMEMPTY:
		len = get_read(handle,data->buffer,sizeof(data->buffer));
		if (len >= 0) {
			obex_headerdata_t hv;
			hv.bs = data->buffer;
			if (len == sizeof(data->buffer))
				(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
							   hv,len,
							   OBEX_FL_STREAM_DATA);
			else
				(void)OBEX_ObjectAddHeader(handle,obj,OBEX_HDR_BODY,
							   hv,len,
							   OBEX_FL_STREAM_DATAEND);			
		} else {
			perror("Reading script output failed");
			obex_send_response(handle, obj, OBEX_RSP_INTERNAL_SERVER_ERROR);
		}
		break;

	case OBEX_EV_LINKERR:
	case OBEX_EV_PARSEERR:
	case OBEX_EV_ABORT:
	case OBEX_EV_REQDONE:
	{
		int err = get_close(handle,(script != NULL));
		if (err)
			fprintf(stderr, "%s\n", strerror(-err));
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		if (data->type) {
			free(data->type);
			data->type = NULL;
		}
		data->length = 0;
		data->time = 0;
	}
		break;
	}
}

void client_eventcb (obex_t* handle, obex_object_t* obj,
		     int __unused mode, int event,
		     int obex_cmd, int __unused obex_rsp)
{
	file_data_t* data = OBEX_GetUserData(handle);
	static int last_obex_cmd = 0;

	/* work-around for openobex bug */
	if (event == OBEX_EV_STREAMAVAIL ||
	    event == OBEX_EV_STREAMEMPTY)
		obex_cmd = last_obex_cmd;
	else
		last_obex_cmd = obex_cmd;

	if (debug) printf("%u: OBEX_EV_%s, OBEX_CMD_%s\n",data->id,
			  obex_events[event],
			  obex_command_string(obex_cmd));

	switch (obex_cmd) {
	case OBEX_CMD_CONNECT:
		obex_action_connect(handle,obj,event);
		break;

	case OBEX_CMD_PUT:
		if (!auth_file || data->net_data->auth_success)
			obex_action_put(handle,obj,event);
		break;

	case OBEX_CMD_GET:
		if (!auth_file || data->net_data->auth_success)
			obex_action_get(handle,obj,event);
		break;

	case OBEX_CMD_DISCONNECT:
		obex_action_disconnect(handle,obj,event);
		break;

	case OBEX_CMD_ABORT:
		if (last_obex_cmd == OBEX_CMD_PUT) {
			obex_action_put(handle,NULL,OBEX_EV_ABORT);
		}
		break;

	default:
		switch (event) {
		case OBEX_EV_REQHINT: /* A new request is coming in */
			/* Reject any other commands */                       
			obex_send_response(handle, obj, OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
	}
}

void* handle_client (void* arg) {
	file_data_t* data = malloc(sizeof(*data));
	char buffer[256];

	if (!data)
		goto out1;
	memset(data,0,sizeof(*data));
	data->id = id++;
	data->child = -1;

	data->net_data = malloc(sizeof(*data->net_data));
	if (!data->net_data)
		goto out2;
	memcpy(data->net_data, OBEX_GetUserData(arg), sizeof(*data->net_data));
	data->net_data->obex = arg;
	if (!data->net_data->obex)
		goto out2;
	OBEX_SetUserData(data->net_data->obex, data);

	memset(buffer, 0, sizeof(buffer));
	net_get_peer(data->net_data, buffer, sizeof(buffer));
	fprintf(stderr,"Connection from \"%s\"\n", buffer);

	do {
		if (OBEX_HandleInput(data->net_data->obex, 10) < 0)
			break;
	} while (1);

out2:
	if (data) {
		if (data->net_data) {
			OBEX_Cleanup(data->net_data->obex);
			free(data->net_data);
		}
		if (data->name)
			free(data->name);
		if (data->type)
			free(data->type);
		free(data);
	}
out1:
	return NULL;
}

void eventcb (obex_t* handle, obex_object_t __unused *obj,
	      int __unused mode, int event,
	      int __unused obex_cmd, int __unused obex_rsp)
{
	if (debug) printf("OBEX_EV_%s, OBEX_CMD_%s\n",
			  obex_events[event],
			  obex_command_string(obex_cmd));
	if (obj && !obex_object_headers(handle,obj)) {
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_BAD_REQUEST,
					OBEX_RSP_BAD_REQUEST);
		return;
	}
	if (event == OBEX_EV_ACCEPTHINT) {
		obex_t* client = OBEX_ServerAccept(handle, client_eventcb, NULL);
		if (!client)
			return;
		if (nofork >= 2) {
			(void)handle_client(client);
		} else {
#if defined(USE_THREADS)
			pthread_t t;
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			if (pthread_create(&t, &attr, handle_client, client) != 0)
				perror("pthread_create()");

#else
			pid_t p = fork();
			switch (p) {
			case 0:
				(void)signal(SIGCHLD, SIG_DFL);
				(void)signal(SIGINT, SIG_DFL);
				(void)signal(SIGTERM, SIG_DFL);
				(void)handle_client(client);
				exit(EXIT_SUCCESS);

			case -1:
				perror("fork()");
			}
#endif
		}
	}
}

#if defined(USE_THREADS)
void obexpushd_listen_thread_cleanup (void* arg) {
	net_cleanup(arg);
}

void* obexpushd_listen_thread (void* arg) {
	struct net_data* data = arg;

	pthread_cleanup_push(obexpushd_listen_thread_cleanup, arg);
	net_init(data, eventcb);
	if (!data->obex) {
		fprintf(stderr, "net_init() failed\n");
		pthread_exit(NULL);
	}
	do {
		if (OBEX_HandleInput(data->obex, 3600) < 0) {
			/* OpenOBEX sometimes return -1 anyway, must be a bug
			 * thus the break is commented -> go on anyway
			 */
			//break;
		}
	} while (1);
	pthread_cleanup_pop(1);
	return NULL;
}
#endif

void print_disclaimer () {
	printf(PROGRAM_NAME " " OBEXPUSHD_VERSION " Copyright (C) 2006-2007 Hendrik Sattler\n"
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
	       " -B[<channel>]  listen to bluetooth connections (default: channel 9)\n"
	       " -I[<app>]      listen to IrDA connections (app example: IrXfer)\n"
#if OPENOBEX_TCPOBEX
	       " -N[<port>]     listen to IPv4/v6 network connections (default: port 650)\n"
#else
	       " -N             listen to IPv4 network connections on port 650\n"
#endif
	       "\n"
	       "Options:\n"
	       " -n             do not detach from terminal\n"
	       " -d             enable debug messages (implies -n)\n"
	       " -p <file>      write pid to file when getting detached\n"
	       " -a <file>      authenticate against credentials from file (EXPERIMENTAL)\n"
	       " -r <file>      use realm credentials from file (EXPERIMENTAL)\n"
	       " -s <file>      define script/program for input/output\n"
	       " -h             this help message\n"
	       " -v             show version\n");
	printf("\n"
	       "See manual page %s(1) for details.\n",me);
}

static char* parse_bluetooth_arg (char* optarg, uint8_t* btchan)
{
	char* tmp;
	char* device = NULL;

	if (strlen(optarg) >= 19 && optarg[0] == '[' && optarg[18] == ']') {
		device = optarg+1;
		device[17] = 0;
		tmp = optarg+19;

	} else if (strncmp(optarg, "hci", 3) == 0) {
		device = optarg;
		tmp = strchr(optarg, (int)':');

	} else {
		tmp = optarg;
	}

	if (tmp) {
		long arg = 0;
		if (*tmp == ':') {
			*tmp = 0;
			++tmp;
		}
		arg = strtol(tmp, NULL, 10);
		if (0 < arg && arg < (1 << 8))
			*btchan = (uint8_t)arg;
	}

	return device;
}

#if OPENOBEX_TCPOBEX
static char* parse_ip_arg (char* optarg, uint16_t* port)
{
	char* device = NULL;

	char* tmp = strchr(optarg, (int)']');
	if (tmp && optarg[0] == '[') { /* IPv6 address */
		device = optarg+1;
		*tmp = 0;
		++tmp;

	} else if (strchr(optarg, (int)'.') != NULL) { /* IPv4 address */
		device = optarg;
		tmp = strchr(optarg, (int)':');
		
	} else { /* no address */
		tmp = optarg;
	}

	if (tmp) {
		long portnum = 0;
		if (*tmp == ':') {
			*tmp = 0;
			++tmp;
		}
		portnum = strtol(tmp, NULL, 10);
		if (portnum > 0 && portnum < (1 << 16))
			*port = portnum;
	}
	return device;
}
#endif

static struct net_data* handle[4] = {
	NULL, NULL, NULL, NULL
};
#define BT_HANDLE         handle[0]
#define IRDA_HANDLE       handle[1]
#define IRDA_EXTRA_HANDLE handle[2]  
#define INET_HANDLE       handle[3]

void obexpushd_shutdown (int sig) {
	size_t i;
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGTERM, SIG_DFL);
	for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
		if (handle[i]) {
			struct net_data* h = handle[i];
			handle[i] = NULL;
			net_cleanup(h);
		}
	}
	(void)kill(getpid(), sig);
}

void obexpushd_wait (int sig) {
	pid_t pidOfChild;
	int status;
	if (sig != SIGCLD)
		return;

	pidOfChild = wait(&status);
	if (WIFEXITED(status))
		fprintf(stderr, "child exited with exit code %d\n", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		fprintf(stderr, "child got signal %d\n", WTERMSIG(status));
}

int main (int argc, char** argv) {
	size_t i;
	char* pidfile = NULL;
#if defined(USE_THREADS)
	pthread_t thread[sizeof(handle)/sizeof(*handle)];
#endif

	int c;
	while ((c = getopt(argc,argv,"B::I::N::a:dhnp:r:s:v")) != -1) {
		switch (c) {
		case 'B':
		{
			char* device = NULL;
			uint8_t btchan = 9;
			if (BT_HANDLE)
				net_cleanup(BT_HANDLE);
			BT_HANDLE = net_data_new();
			if (optarg) {
				device = parse_bluetooth_arg(optarg, &btchan);
			}
			if (bluetooth_setup(BT_HANDLE, device, btchan)) {
				net_cleanup(BT_HANDLE);
				BT_HANDLE = NULL;
			}
			break;
		}

		case 'I':
			if (IRDA_EXTRA_HANDLE) {
				net_cleanup(IRDA_EXTRA_HANDLE);
				IRDA_EXTRA_HANDLE = NULL;
			}
			if (IRDA_HANDLE)
				net_cleanup(IRDA_HANDLE);
			IRDA_HANDLE = net_data_new();
			if (irda_setup(IRDA_HANDLE, NULL)) {
				net_cleanup(IRDA_HANDLE);
				IRDA_HANDLE = NULL;
			}
			if (optarg) {
				IRDA_EXTRA_HANDLE = net_data_new();
				if (irda_setup(IRDA_EXTRA_HANDLE, optarg)) {
					net_cleanup(IRDA_EXTRA_HANDLE);
					IRDA_EXTRA_HANDLE = NULL;
				}
			}
			break;

		case 'N':
		{
#if OPENOBEX_TCPOBEX
			char* address = NULL;
			uint16_t port = 650;

			if (optarg) {
				address = parse_ip_arg(optarg, &port);
			}
#endif
			if (INET_HANDLE)
				net_cleanup(INET_HANDLE);
			INET_HANDLE = net_data_new();
#if OPENOBEX_TCPOBEX
			if (tcp_setup(INET_HANDLE, address, port))
#else
			if (inet_setup(INET_HANDLE))
#endif
			{
				net_cleanup(INET_HANDLE);
				INET_HANDLE = NULL;
			}
			break;
		}

		case 'd':
			debug = 1;
			/* no break */

		case 'n':
			++nofork;
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

	/* check that at least one listener was enabled */
	for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
		if (handle[i])
			break;
	}
	if (i == sizeof(handle)/sizeof(*handle)) {
		BT_HANDLE = net_data_new();
		if (bluetooth_setup(BT_HANDLE, NULL, 9)) {
			net_cleanup(BT_HANDLE);
			exit(EXIT_FAILURE);
		}
	}
		
	/* fork if allowed (detach from terminal) */
	if (nofork < 1) {
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

	/* setup the signal handlers */
	(void)signal(SIGINT, obexpushd_shutdown);
	(void)signal(SIGTERM, obexpushd_shutdown);

#if defined(USE_THREADS)
	/* initialize all enabled listeners */
	for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
		if (!handle[i])
			continue;
		if (pthread_create(&thread[i], NULL, obexpushd_listen_thread, handle[i]) != 0)
			perror("pthread_create()");
	}

	for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
		if (handle[i]) {
			void* retval;
			pthread_join(thread[i], &retval);
		}
	}
	pthread_exit(NULL);

#else
	(void)signal(SIGCHLD, obexpushd_wait);

	/* initialize all enabled listeners */
	for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
		int fd = -1;
		if (!handle[i])
			continue;
		net_init(handle[i], eventcb);
		if (!handle[i]->obex)
			exit(EXIT_FAILURE);
		fd = OBEX_GetFD(handle[i]->obex);
		if (fd == -1) {
			perror("OBEX_GetFD()");
			exit(EXIT_FAILURE);
		}
	}
	
	/* run the multiplexer */
	do {
		int topfd = 0;
		fd_set fds;
		FD_ZERO(&fds);
		for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
			if (!handle[i])
				continue;
			if (handle[i]->obex) {
				int fd = OBEX_GetFD(handle[i]->obex);
				if (fd == -1) {
					perror("OBEX_GetFD()");
					exit(EXIT_FAILURE);
				}
				if (fd > topfd)
					topfd = fd;
				FD_SET(fd, &fds);
			}
		}
		select(topfd+1, &fds, NULL, NULL, NULL);
		for (i = 0; i < sizeof(handle)/sizeof(*handle); ++i) {
			int fd = -1;
			if (!handle[i])
				continue;
			if (!handle[i]->obex)
				continue;
			fd = OBEX_GetFD(handle[i]->obex);
			if (FD_ISSET(fd,&fds))
				(void)OBEX_HandleInput(handle[i]->obex,1);
		}			
	} while (1);
#endif

	/* never reached */
	return EXIT_FAILURE;
}
