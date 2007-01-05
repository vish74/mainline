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

#include "obexpush-sdp.h"
#include "obex_auth.h"
#include "obexpushd.h"
#include "data_io.h"
#include "utf.h"
#include "md5.h"

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

/* global settings */
static int debug = 0;
static int nofork = 0;
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
			   const uint8_t* user, size_t ulen,
			   /*@out@*/ uint8_t* pass, size_t size)
{
	ssize_t ret = 0;
	size_t lsize = ulen+1+size+3;
	char* line = malloc(lsize);
	int status;
	FILE* f;
	
	if (!line)
		return -ENOMEM;
	if (file[0] == '|') {
		char* args[2] = { file+1, (char*)user };
		status = pipe_open(args[0],args,O_RDONLY);
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

void obex_object_headers (obex_t* handle, obex_object_t* obj) {
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
	file_data_t* data = OBEX_GetUserData(handle);
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		if (auth_file && !data->auth_success) {
			struct obex_auth_challenge chal;
			if (get_nonce(chal.nonce) < 0)
				(void)OBEX_ObjectSetRsp(obj,
							OBEX_RSP_SERVICE_UNAVAILABLE,
							OBEX_RSP_SERVICE_UNAVAILABLE);
			memcpy(data->nonce,chal.nonce,sizeof(data->nonce));
			chal.opts = OBEX_AUTH_OPT_USER_REQ|OBEX_AUTH_OPT_FULL_ACC;
			chal.realm = NULL;
			(void)obex_auth_add_challenge(handle,obj,&chal);
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
	file_data_t* data = OBEX_GetUserData(handle);

	obex_object_headers(handle,obj);
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
		(void)OBEX_ObjectReadStream(handle,obj,NULL);
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
		if (data->out == NULL &&
		    put_open(handle,script) < 0)
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_FORBIDDEN,
						OBEX_RSP_FORBIDDEN);
		break;

	case OBEX_EV_STREAMAVAIL:
	{
		const uint8_t* buf = NULL;
		int len = OBEX_ObjectReadStream(handle,obj,&buf);

		if (debug) printf("%u.%u: got %d bytes of streamed data\n",data->id,data->count,len);
		if (len)
			if (/* (data == NULL && put_open(handle,script) < 0) || */
			    put_write(handle,buf,len))
				(void)OBEX_ObjectSetRsp(obj,
							OBEX_RSP_FORBIDDEN,
							OBEX_RSP_FORBIDDEN);
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
	}
}

void obex_action_get (obex_t* handle, obex_object_t* obj, int event) {
	file_data_t* data = OBEX_GetUserData(handle);
	int len = 0;

	obex_object_headers(handle,obj);
	switch (event) {
	case OBEX_EV_REQHINT: /* A new request is coming in */
		if (!script) {
			/* There is no default object to get */
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_NOT_FOUND,
						OBEX_RSP_NOT_FOUND);
			break;
		}
		if (data->name) {
			free(data->name);
			data->name = NULL;
		}
		/* in case that there is no TYPE header */
		data->type = strdup("text/x-vcard");
		data->count += 1;
		data->length = 0;
		data->time = 0;
		break;

	case OBEX_EV_REQCHECK:
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
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_FORBIDDEN,
						OBEX_RSP_FORBIDDEN);

		if (get_open(handle,script) < 0 ||
		    data->length == 0) {
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_INTERNAL_SERVER_ERROR,
						OBEX_RSP_INTERNAL_SERVER_ERROR);
		}
		break;

	case OBEX_EV_REQ: {
		obex_headerdata_t hv;
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
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
			(void)OBEX_ObjectSetRsp(obj,
						OBEX_RSP_INTERNAL_SERVER_ERROR,
						OBEX_RSP_INTERNAL_SERVER_ERROR);
		}
		break;

	case OBEX_EV_REQDONE:
		(void)get_close(handle,(script != NULL));
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

void handle_client (obex_t* client, listener_data_t* l) {
	int status = 0;
	file_data_t* data = malloc(sizeof(*data));

	if (!client)
		exit(EXIT_FAILURE);
	if (data) memset(data,0,sizeof(*data));
	data->id = id++;
	data->intf = l->intf;
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
	if (nofork < 2)
		exit(EXIT_SUCCESS);
}

void eventcb (obex_t* handle, obex_object_t __unused *obj,
	      int __unused mode, int event,
	      int __unused obex_cmd, int __unused obex_rsp)
{
	listener_data_t* l = OBEX_GetCustomData(handle);
	if (debug) printf("OBEX_EV_%s, OBEX_CMD_%s\n",
			  obex_events[event],
			  obex_commands[obex_cmd]);
	if (obj) obex_object_headers(handle,obj);
	switch (event) {
	case OBEX_EV_ACCEPTHINT:
	{
		obex_t* client = OBEX_ServerAccept(handle,client_eventcb,NULL);
		if (client && (nofork >= 2 || fork() == 0))
			handle_client(client,l);
	}
	break;
	}
}

/*@null@*/
obex_t* inet_listen (void) {
	obex_t* handle = OBEX_Init(OBEX_TRANS_INET,eventcb,OBEX_FL_KEEPSERVER);
	
	if (handle) {
		(void)InOBEX_ServerRegister(handle);
	}
	if (handle) {
		listener_data_t* l = malloc(sizeof(*l));
		if (l == NULL) {
			perror("OBEX_GetFD(BT_HANDLE)");
			exit(EXIT_FAILURE);
		}
		l->intf = INTF_INET;
		OBEX_SetCustomData(handle,l);
	}
	return handle;
}

/*@null@*/
obex_t* irda_listen (char* service) {
	obex_t* handle = OBEX_Init(OBEX_TRANS_IRDA,eventcb,OBEX_FL_KEEPSERVER);
	
	if (handle) {
		(void)IrOBEX_ServerRegister(handle,service);
		fprintf(stderr,"Listening on IrDA service \"%s\"\n", service);
	}
	if (handle) {
		listener_data_t* l = malloc(sizeof(*l));
		if (l == NULL) {
			perror("OBEX_GetFD(BT_HANDLE)");
			exit(EXIT_FAILURE);
		}
		l->intf = INTF_IRDA;
		OBEX_SetCustomData(handle,l);
	}
	return handle;
}

/*@null@*/
obex_t* bluetooth_listen (uint8_t channel) {
	obex_t* handle = OBEX_Init(OBEX_TRANS_BLUETOOTH,eventcb,OBEX_FL_KEEPSERVER);
  
	if (handle) {
		if (BtOBEX_ServerRegister(handle,BDADDR_ANY,channel)) {
			sdp_session_t* session = bt_sdp_session_open(channel);
			fprintf(stderr,"Listening on bluetooth channel %u\n",(unsigned int)channel);
			if (!session) {
				OBEX_Cleanup(handle);
				handle = NULL;
			}
		}
	}
	if (handle) {
		listener_data_t* l = malloc(sizeof(*l));
		if (l == NULL) {
			perror("OBEX_GetFD(BT_HANDLE)");
			exit(EXIT_FAILURE);
		}
		l->intf = INTF_BLUETOOTH;
		OBEX_SetCustomData(handle,l);
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
	       " -N             listen to IP Network connections\n"
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

int main (int argc, char** argv) {
	int retval = EXIT_SUCCESS;
	int c;
	intf_t intf = 0;
	uint8_t btchan = 9;
	char* irda_extra = NULL;
	char* pidfile = NULL;
	
	obex_t* handle[4] = { NULL, NULL, NULL, NULL };
#define BT_HANDLE         handle[0]
#define IRDA_HANDLE       handle[1]
#define IRDA_EXTRA_HANDLE handle[2]  
#define INET_HANDLE       handle[3]
	int topfd = 0;
	
	while ((c = getopt(argc,argv,"B::I::Na:dhnp:r:s:v")) != -1) {
		switch (c) {
		case 'B':
			intf |= (1 << INTF_BLUETOOTH);
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
			intf |= (1 << INTF_IRDA);
			irda_extra = optarg;
			break;

		case 'N':
			intf |= (1 << INTF_INET);
			break;

		case 'd':
			debug = 1;
			/* no break */

		case 'n':
			if (nofork)
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
	if (intf == 0) intf |= (1 << INTF_BLUETOOTH);
	
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
	
	if (intf & (1 << INTF_BLUETOOTH)) {
		int fd = -1;
		BT_HANDLE = bluetooth_listen(btchan);
		if (BT_HANDLE)
			fd = OBEX_GetFD(BT_HANDLE);
		if (fd == -1) {
			perror("OBEX_GetFD(BT_HANDLE)");
			exit(EXIT_FAILURE);
		}
		if (fd > topfd)
			topfd = fd;
	}
	if (intf & (1 << INTF_IRDA)) {
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
	if (intf & (1 << INTF_INET)) {
		int fd = -1;
		INET_HANDLE = inet_listen();
		if (INET_HANDLE)
			fd = OBEX_GetFD(INET_HANDLE);
		if (fd == -1) {
			perror("OBEX_GetFD(INET_HANDLE)");
			exit(EXIT_FAILURE);
		}
		if (fd > topfd)
			topfd = fd;
	}

	++topfd;
	
	(void)signal(SIGCLD, SIG_IGN);
	do {
		int fd = -1;
		fd_set fds;
		FD_ZERO(&fds);
		if (intf & (1 << INTF_BLUETOOTH))
			FD_SET(OBEX_GetFD(BT_HANDLE),&fds);
		if (intf & (1 << INTF_IRDA)) {
			FD_SET(OBEX_GetFD(IRDA_HANDLE),&fds);
			if (irda_extra)
				FD_SET(OBEX_GetFD(IRDA_EXTRA_HANDLE),&fds);
		}
		if (intf & (1 << INTF_INET))
			FD_SET(OBEX_GetFD(INET_HANDLE),&fds);
		select(topfd,&fds,NULL,NULL,NULL);
		if (intf & (1 << INTF_BLUETOOTH)) {
			fd = OBEX_GetFD(BT_HANDLE);
			if (FD_ISSET(fd,&fds))
				(void)OBEX_HandleInput(BT_HANDLE,1);
		}
		if (intf & (1 << INTF_IRDA)) {
			fd = OBEX_GetFD(IRDA_HANDLE);
			if (FD_ISSET(fd,&fds))
				(void)OBEX_HandleInput(IRDA_HANDLE,1);
			if (irda_extra) {
				fd = OBEX_GetFD(IRDA_EXTRA_HANDLE);
				if (FD_ISSET(fd,&fds))
					(void)OBEX_HandleInput(IRDA_EXTRA_HANDLE,1);	  
			}
		}
		if (intf & (1 << INTF_INET)) {
			fd = OBEX_GetFD(INET_HANDLE);
			if (FD_ISSET(fd,&fds))
				(void)OBEX_HandleInput(INET_HANDLE,1);
		}
	} while (1);
	
	return retval;
}
