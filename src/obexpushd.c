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
				(void)fprintf(stderr, "%u.%u: ", data->id, data->count);
			else
				(void)fprintf(stderr, "%u: ", data->id);
		}
		va_start(ap, format);
		vfprintf(stderr, format, ap);
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

void obex_send_response (file_data_t* data, obex_object_t* obj, uint8_t respCode)
{
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
void client_eventcb (obex_t* handle, obex_object_t* obj,
		     int mode, int event,
		     int obex_cmd, int obex_rsp)
{
	file_data_t* data = OBEX_GetUserData(handle);

	if (debug)
		dbg_printf(data, "OBEX_EV_%s, OBEX_CMD_%s\n",
			   obex_event_string(event),
			   obex_command_string(obex_cmd));

	obex_action_eventcb(handle, obj, mode, event, obex_cmd, obex_rsp);
}

static
file_data_t* create_client (struct net_data *net) {
	file_data_t* data = malloc(sizeof(*data));

	if (data) {
		memset(data,0,sizeof(*data));
		data->id = id++;
		data->net_data = net;
		data->auth = auth_copy(auth);
		data->io = io_copy(io);
	}
	return data;
}

static
void cleanup_client (file_data_t *data) {
	if (data->transfer.peername) {
		free(data->transfer.peername);
		data->transfer.peername = NULL;
	}
	if (data->transfer.name) {
		free(data->transfer.name);
		data->transfer.name = NULL;
	}
	if (data->transfer.path) {
		free(data->transfer.path);
		data->transfer.path = NULL;
	}
	if (data->transfer.type) {
		free(data->transfer.type);
		data->transfer.type = NULL;
	}
	if (data->auth) {
		auth_destroy(data->auth);
		data->auth = NULL;
	}
	if (data->io) {
		io_destroy(data->io);
		data->io = NULL;
	}
	free(data);
}

static void* handle_client (void* arg) {
	obex_t *obex = arg;
	struct net_data *old_net = OBEX_GetUserData(obex);
	file_data_t *data = create_client(old_net);

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
			dbg_printf(data, "Connection from \"%s\"\n", buffer);

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
		file_data_t *data;
		struct net_data *net;

		/* This handles connections that can only handle one client at a time.
		 */
		if (event == OBEX_EV_REQHINT &&
		    obex_cmd == OBEX_CMD_CONNECT)
		{
			net = OBEX_GetUserData(handle);
			data = create_client(net);

			OBEX_SetUserData(handle, data);

		} else {
			data = OBEX_GetUserData(handle);
			net = data->net_data;
		}
		obex_action_eventcb(handle, obj, mode, event, obex_cmd, obex_rsp);
		if (event == OBEX_EV_REQDONE &&
		    obex_cmd == OBEX_CMD_DISCONNECT)
		{
			OBEX_SetUserData(handle, net);
			cleanup_client(data);
		}
	}
}

#if defined(USE_THREADS)
#include "pthreads.c"
#else
#include "fork.c"
#endif

static void print_disclaimer () {
	fprintf(stderr,
		PROGRAM_NAME " " OBEXPUSHD_VERSION " Copyright (C) 2006-2010 Hendrik Sattler\n"
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
	       " -S             handle one connection via stdin/stdout\n"
	       "\n"
	       "Options:\n"
	       " -n             do not detach from terminal\n"
	       " -d             enable debug messages (implies -n)\n"
	       " -p <file>      write pid to file when getting detached\n"
	       " -A             use transport layer specific access rules if available\n"
	       " -a <file>      authenticate against credentials from file (EXPERIMENTAL)\n"
	       " -o <directory> change base directory\n"
	       " -s <file>      define script/program for input/output\n"
	       " -t <protocol>  add a protocol (OPP, FTP)\n"
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
	IDX_STDIO,
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
	uint8_t protocols = 0;

	(void)setlocale(LC_CTYPE, "");
	io = io_file_init(".");

	for (i = 0; i < NET_INDEX_MAX; ++i) {
		handle[i] = NULL;
	}
	memset(data, 0, sizeof(data));

	while (c != -1) {
		c = getopt(argc,argv,"B::I::N::G:SAa:dhnp:r:o:s:t:v");
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

		case 'S':
			if (handle[IDX_STDIO])
					net_handler_cleanup(handle[IDX_STDIO]);
			handle[IDX_STDIO] = fdobex_setup(STDIN_FILENO, STDOUT_FILENO, 0);
			break;

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

		case 't':
			if (optarg) {
				if (strcasecmp(optarg, "FTP") == 0)
					protocols |= (1 << NET_OBEX_FTP);
			}
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
	if (nofork < 1 && !handle[IDX_STDIO]) {
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
			fprintf(stderr, "Warning: local character set is not Unicode.\n");
	}

	/* setup the signal handlers */
	(void)signal(SIGINT, obexpushd_shutdown);
	(void)signal(SIGTERM, obexpushd_shutdown);

	protocols |= (1 << NET_OBEX_PUSH);

	/* initialize all enabled listeners */
	for (i = 0; i < NET_INDEX_MAX; ++i) {
		if (!handle[i])
			continue;
		data[i].handler = handle[i];
		data[i].auth_level = auth_level;
		data[i].enabled_protocols = protocols;
	}

	if (obexpushd_start(data, NET_INDEX_MAX) != 0)
		perror("Failed to start");

	/* never reached */
	return EXIT_FAILURE;
}
