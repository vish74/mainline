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

#include <bluetooth/bluetooth.h>
#include "obex_auth.h"
#include "obexpushd.h"
#include "io.h"
#include "utf.h"
#include "net.h"
#include "action.h"

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
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <locale.h>
#include <langinfo.h>

#define PROGRAM_NAME "obexpushd"
#include "version.h"
#include "compiler.h"

/* global settings */
int debug = 0;
static int nofork = 0;
static int id = 0;
static struct auth_handler* auth = NULL;
static struct io_handler* io = NULL;

#define EOL(n) ((n) == '\n' || (n) == '\r')

void dbg_printf (file_data_t *data, const char *format, ...)
{
	if (debug) {
		va_list ap;
		if (data) {
			if (data->count)
				(void)fprintf(stdout, "%u.%u: ", data->id, data->count);
			else
				(void)fprintf(stdout, "%u: ", data->id);
		}
		va_start(ap, format);
		vfprintf(stdout, format, ap);
		va_end(ap);
	}
}

static const char* obex_event_string(uint8_t event)
{
	static const char* obex_events[] = {
		"PROGRESS", "REQHINT", "REQ", "REQDONE",
		"LINKERR", "PARSEERR", "ACCEPTHINT", "ABORT",
		"STREAMEMPTY", "STREAMAVAIL", "UNEXPECTED", "REQCHECK",
	};

	return obex_events[event];
}

static const char* obex_command_string(uint8_t cmd)
{
	static const char* obex_commands[] = {
		"CONNECT", "DISCONNECT", "PUT", "GET",
		"SETPATH", "SESSION", "ABORT"
	};

	switch (cmd) {
	case OBEX_CMD_CONNECT:
	case OBEX_CMD_DISCONNECT:
	case OBEX_CMD_PUT:
	case OBEX_CMD_GET:
		return obex_commands[cmd];
	case OBEX_CMD_SETPATH:
		return obex_commands[4];
	case OBEX_CMD_SESSION:
		return obex_commands[5];
	case OBEX_CMD_ABORT:
		return obex_commands[6];
	default:
		return "UNKNOWN";
	}
}

void obex_send_response (obex_t* handle, obex_object_t* obj, uint8_t respCode) {
	file_data_t* data = OBEX_GetUserData(handle);

	dbg_printf(data, "Sending response code %u\n", ((respCode >> 4) * 100) + (respCode & 0xF));
	switch (respCode) {
	case 0:
	case OBEX_RSP_CONTINUE:
	case OBEX_RSP_SUCCESS:
		(void)OBEX_ObjectSetRsp(obj,
					OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
		break;

	default:
		(void)OBEX_ObjectSetRsp(obj, respCode, respCode);
		break;
	}
}

static
void common_eventcb (obex_t* handle, obex_object_t* obj,
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

	switch (obex_cmd) {
	case OBEX_CMD_CONNECT:
		obex_action_connect(handle,obj,event);
		break;

	case OBEX_CMD_PUT:
		if (net_security_check(data->net_data))
			obex_action_put(handle,obj,event);
		break;

	case OBEX_CMD_GET:
		if (net_security_check(data->net_data))
			obex_action_get(handle,obj,event);
		break;

	case OBEX_CMD_SETPATH:
		if (net_security_check(data->net_data))
			obex_action_setpath(handle,obj,event);
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

static
void client_eventcb (obex_t* handle, obex_object_t* obj,
		     int mode, int event,
		     int obex_cmd, int obex_rsp)
{
	file_data_t* data = OBEX_GetUserData(handle);

	if (debug)
		printf("%u: OBEX_EV_%s, OBEX_CMD_%s\n", data->id,
		       obex_event_string(event), obex_command_string(obex_cmd));

	common_eventcb(handle, obj, mode, event, obex_cmd, obex_rsp);
}

static
file_data_t* create_client (obex_t *obex) {
	file_data_t* data = malloc(sizeof(*data));

	if (data) {
		memset(data,0,sizeof(*data));
		data->id = id++;
		data->net_data = OBEX_GetUserData(obex);
		data->auth = auth_copy(auth);
		data->io = io_copy(io);
	}
	return data;
}

static
void cleanup_client (file_data_t *data) {
	if (data->transfer.name)
		free(data->transfer.name);
	if (data->transfer.type)
		free(data->transfer.type);
	free(data);
}

static void* handle_client (void* arg) {
	obex_t *obex = arg;
	file_data_t *data = create_client(obex);

	if (data) {
		/* create new net_data for this client */
		struct net_data *net = net_data_new();

		if (net) {
			char buffer[256];

			memcpy(net, data->net_data, sizeof(*net));
			net->obex = obex;
			data->net_data = net;

			OBEX_SetUserData(obex, data);

			memset(buffer, 0, sizeof(buffer));
			net_get_peer(data->net_data, buffer, sizeof(buffer));
			fprintf(stderr,"Connection from \"%s\"\n", buffer);

			do {
				if (OBEX_HandleInput(data->net_data->obex, 10) < 0)
					break;
			} while (1);
		}

		if (data->net_data) {
			OBEX_Cleanup(data->net_data->obex);
			free(data->net_data);
		}
		cleanup_client(data);
	}
	return NULL;
}

int obexpushd_create_instance (void* (*cb)(void*), void *cbdata);
int obexpushd_start (struct net_data *data, unsigned int count);

static
void create_instance (void* (*cb)(void*), void *cbdata) {
	if (nofork >= 2) {
		(void)cb(cbdata);
	} else {
		int err = obexpushd_create_instance(cb, cbdata);
		if (err != 0) {
			errno = -err;
			perror("Failed to create instance");
		}
	}
}

static
void eventcb (obex_t* handle, obex_object_t __unused *obj,
	      int mode, int event,
	      int obex_cmd, int obex_rsp)
{
	dbg_printf(NULL, "OBEX_EV_%s, OBEX_CMD_%s\n",
		   obex_event_string(event), obex_command_string(obex_cmd));

	if (event == OBEX_EV_ACCEPTHINT) {
		obex_t *client = OBEX_ServerAccept(handle, client_eventcb, NULL);
		if (client) {
			int fd;

			fd = OBEX_GetFD(client);
			if (fd >= 0)
				(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
			create_instance(handle_client, client);
		}

	} else {
		/* This handles connections that can only handle one client at a time.
		 */
		file_data_t *data;
		
		switch (obex_cmd) {
		case OBEX_CMD_CONNECT:
			if (obex_cmd == OBEX_EV_REQHINT) {
				data = create_client(handle);
				OBEX_SetUserData(handle, data);
			}
			break;

		case OBEX_CMD_DISCONNECT:
			if (obex_cmd == OBEX_EV_REQHINT) {
				data = OBEX_GetUserData(handle);
				OBEX_SetUserData(handle, data->net_data);
				cleanup_client(data);
			}
			break;
		}

		common_eventcb(handle, obj, mode, event, obex_cmd, obex_rsp);
	}
}

#if defined(USE_THREADS)
#include "pthreads.c"
#else
#include "fork.c"
#endif

static void print_disclaimer () {
	printf(PROGRAM_NAME " " OBEXPUSHD_VERSION " Copyright (C) 2006-2009 Hendrik Sattler\n"
	       "This software comes with ABSOLUTELY NO WARRANTY.\n"
	       "This is free software, and you are welcome to redistribute it\n"
	       "under certain conditions.\n");
}

static void print_help (char* me) {
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
#ifdef USB_GADGET_SUPPORT
	       " -G<device>     listen on an USB gadget device file\n"
#endif
	       "\n"
	       "Options:\n"
	       " -n             do not detach from terminal\n"
	       " -d             enable debug messages (implies -n)\n"
	       " -p <file>      write pid to file when getting detached\n"
	       " -A             use transport layer specific access rules if available\n"
	       " -a <file>      authenticate against credentials from file (EXPERIMENTAL)\n"
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

	} else if (optarg[0] == '*' && optarg[1] == ':') {
		device = optarg;
		tmp = optarg+1;
		
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

enum net_index {
	IDX_BT = 0,
	IDX_IRDA,
	IDX_IRDA_EXTRA,
	IDX_INET,
#ifdef USB_GADGET_SUPPORT
	IDX_GADGET,
#endif
	NET_INDEX_MAX
};

static struct net_data data[NET_INDEX_MAX];
static void obexpushd_shutdown (int sig) {
	size_t i;

	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGTERM, SIG_DFL);
	for (i = 0; i < NET_INDEX_MAX; ++i)
		net_cleanup(&data[i]);

	(void)kill(getpid(), sig);
}

int main (int argc, char** argv) {
	size_t i;
	char* pidfile = NULL;
	uint8_t auth_level = 0;
	int c = 0;
	struct net_handler* handle[NET_INDEX_MAX];

	(void)setlocale(LC_CTYPE, "");
	io = io_file_init(".");

	for (i = 0; i < NET_INDEX_MAX; ++i) {
		handle[i] = NULL;
	}
	memset(data, 0, sizeof(data));

	while (c != -1) {
		c = getopt(argc,argv,"B::I::N::G:Aa:dhnp:r:o:s:v");
		switch (c) {
		case -1: /* processed all options, no error */
			break;

		case 'B':
		{
			char* device = NULL;
			uint8_t btchan = 9;

			if (handle[IDX_BT])
				net_handler_cleanup(handle[IDX_BT]);
			if (optarg) {
				device = parse_bluetooth_arg(optarg, &btchan);
			}
			handle[IDX_BT] = bluetooth_setup(device, btchan);
			if (!handle[IDX_BT]) {
				perror("Setting up bluetooth failed");
			}
			break;
		}

		case 'I':
			if (handle[IDX_IRDA_EXTRA]) {
				net_handler_cleanup(handle[IDX_IRDA_EXTRA]);
				handle[IDX_IRDA_EXTRA] = NULL;
			}
			if (handle[IDX_IRDA])
				net_handler_cleanup(handle[IDX_IRDA]);
			handle[IDX_IRDA] = irda_setup(NULL);
			if (!handle[IDX_IRDA]) {
				perror("Setting up IrDA failed");
			}
			if (optarg) {
				handle[IDX_IRDA_EXTRA] = irda_setup(optarg);
				if (!handle[IDX_IRDA_EXTRA]) {
					perror("Setting up IrDA failed");
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
			if (handle[IDX_INET])
				net_handler_cleanup(handle[IDX_INET]);
#if OPENOBEX_TCPOBEX
			handle[IDX_INET] = tcp_setup(address, port);
#else
			handle[IDX_INET] = inet_setup();
#endif
			if (!handle[IDX_INET]){
				perror("Setting up TCP failed");
			}
			break;
		}
#ifdef USB_GADGET_SUPPORT
		case 'G':
			if (optarg) {
				if (handle[IDX_GADGET])
					net_handler_cleanup(handle[IDX_GADGET]);
				handle[IDX_GADGET] = usb_gadget_setup(optarg, 0);
			}
			break;
#endif
		case 'd':
			debug = 1;
			/* no break */

		case 'n':
			++nofork;
			break;

		case 'p':
			pidfile = optarg;
			break;

		case 'A':
			auth_level |= AUTH_LEVEL_TRANSPORT;
			break;

		case 'a':
			if (auth)
				auth_destroy(auth);
			auth = auth_file_init(optarg, NULL, OBEX_AUTH_OPT_USER_REQ);
			auth_level |= AUTH_LEVEL_OBEX;
			break;

		case 'r':
			fprintf(stderr, "This version does not support obex server authentication.\n");
			return EXIT_FAILURE;
			break;

		case 'o':
			if (io)
				io_destroy(io);
			io = io_file_init(optarg);
			break;

		case 's':
			if (io)
				io_destroy(io);
			io = io_script_init(optarg);
			break;

		case 'h':
			print_help(PROGRAM_NAME);
			exit(EXIT_SUCCESS);

		case 'v':
			printf("%s\n",OBEXPUSHD_VERSION);
			exit(EXIT_SUCCESS);
		}
	}

	/* check that the file/script output is valid */
	if (!io) {
		fprintf(stderr, "Invalid output options\n");
		exit(EXIT_SUCCESS);
	}

	/* check that at least one listener was enabled */
	for (i = 0; i < NET_INDEX_MAX; ++i) {
		if (handle[i])
			break;
	}
	if (i == NET_INDEX_MAX) {
		handle[IDX_BT] = bluetooth_setup(NULL, 9);
		if (!handle[IDX_BT]) {
			perror("Setting up bluetooth failed");
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
		if (strcasecmp(nl_langinfo(CODESET), "UTF-8") != 0)
			printf("Warning: local character set is not Unicode.\n");
	}

	/* setup the signal handlers */
	(void)signal(SIGINT, obexpushd_shutdown);
	(void)signal(SIGTERM, obexpushd_shutdown);

	/* initialize all enabled listeners */
	for (i = 0; i < NET_INDEX_MAX; ++i) {
		if (!handle[i])
			continue;
		data[i].handler = handle[i];
		data[i].auth_level = auth_level;
	}

	if (obexpushd_start(data, NET_INDEX_MAX) != 0)
		perror("Failed to start");

	/* never reached */
	return EXIT_FAILURE;
}
