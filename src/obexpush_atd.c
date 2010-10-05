 /* Copyright (C) 2010 Hendrik Sattler <post@hendrik-sattler.de>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <errno.h>
#include <limits.h>

#if defined(USE_SPAWN)
#include <spawn.h>
#endif

#include "compiler.h"

#define VENDOR "Hendrik Sattler"
#define MODEL  "ObexPushD AT wrapper, use AT+CPROT=1 to CONNECT"
#define REVISION "1.0"

enum at_status {
	AT_STATUS_OK = 0,
	AT_STATUS_ERROR,
};

static struct termios t;
static char buffer[2048];
static size_t buflen;

static char s3 = '\r';
static char s4 = '\n';
static char s5 = '\b';
static bool echo = true;
static bool quiet = false;
static bool verbose = true;

#define debug_print(line, ...) fprintf(stderr, line, ##__VA_ARGS__)

static void print_line(const char *line)
{
	debug_print("<- \"%s\"  (verbose=%d)\n", line, verbose);
	if (verbose) {
		printf("%c%c%s%c%c", s3, s4, line, s3, s4);
	} else {
		printf("%s%c%c", line, s3, s4);
	}
}

static void print_result_code(const char *line, int code)
{
	debug_print("<- \"%s\" (quiet=%d, verbose=%d)\n",
		    line, quiet, verbose);
	if (!quiet) {
		if (verbose) {
			printf("%c%c%s%c%c", s3, s4, line, s3, s4);
		} else {
			printf("%d%c", code, s3);
		}
	}
}

static int at_none(const char __unused *cmd, size_t __unused cmdlen)
{
	return AT_STATUS_OK;
}

static int at_reset(const char __unused *cmd, size_t __unused cmdlen)
{
	s3 = '\r';
	s4 = '\n';
	s5 = '\b';
	echo = true;
	quiet = false;
	verbose = true;
	return AT_STATUS_OK;
}

static int at_set_s(char *s, const char *cmd, size_t cmdlen)
{
	if (cmd[cmdlen] == '=') {
		char *endptr;
		long value = strtol(cmd+cmdlen+1, &endptr, 10);

		if (cmd+cmdlen == endptr &&
		    0 <= value && value <= CHAR_MAX)
		{
			*s = (char)value;
			return AT_STATUS_OK;
		}

	} else if (cmd[cmdlen] == '?') {
		char line[4];

		snprintf(line, 4, "%03d", *s);
		print_line(line);

		return AT_STATUS_OK;
	}

	return AT_STATUS_ERROR;
}

static int at_set_s3(const char *cmd, size_t cmdlen)
{
	return at_set_s(&s3, cmd, cmdlen);
}

static int at_set_s4(const char *cmd, size_t cmdlen)
{
	return at_set_s(&s4, cmd, cmdlen);
}

static int at_set_s5(const char *cmd, size_t cmdlen)
{
	return at_set_s(&s5, cmd, cmdlen);
}

static int at_disable_echo(const char __unused *cmd, size_t __unused cmdlen)
{
	echo = false;
	return AT_STATUS_OK;
}

static int at_enable_echo(const char __unused *cmd, size_t __unused cmdlen)
{
	echo = true;
	return AT_STATUS_OK;
}

static int at_disable_quiet(const char __unused *cmd, size_t __unused cmdlen)
{
	quiet = false;
	return AT_STATUS_OK;
}

static int at_enable_quiet(const char __unused *cmd, size_t __unused cmdlen)
{
	quiet = true;
	return AT_STATUS_OK;
}

static int at_disable_verbose(const char __unused *cmd, size_t __unused cmdlen)
{
	verbose = false;
	return AT_STATUS_OK;
}

static int at_enable_verbose(const char __unused *cmd, size_t __unused cmdlen)
{
	verbose = true;
	return AT_STATUS_OK;
}

static int at_me_vendor(const char *cmd, size_t cmdlen)
{
	if (strlen(cmd+cmdlen) == 0) {
		print_line(VENDOR);
		return AT_STATUS_OK;
	} else
		return AT_STATUS_ERROR;
}

static int at_me_model(const char *cmd, size_t cmdlen)
{
	if (strlen(cmd+cmdlen) == 0) {
		print_line(MODEL);
		return AT_STATUS_OK;
	} else
		return AT_STATUS_ERROR;
}

static int at_me_revision(const char *cmd, size_t cmdlen)
{
	if (strlen(cmd+cmdlen) == 0) {
		print_line(REVISION);
		return AT_STATUS_OK;
	} else
		return AT_STATUS_ERROR;
}

static int start_obex_server(pid_t *p)
{
	char *args[] = {"obexpushd", "-S", "-t", "FTP", NULL};

#if defined(USE_SPAWN)
	return posix_spawnp(p, args[0], NULL, NULL, args, environ);

#else
	*p = fork();
	if (*p == 0) {
		/* child */
		execvp(args[0], args);
		perror("execvp");
		exit(EXIT_FAILURE);

	} else {
		if (*p == -1)
			return errno;
		else
			return 0;
	}
#endif		
}

static int at_enter_protocol(const char *cmd, size_t cmdlen)
{
	const char *args = &cmd[cmdlen];

	if (strcmp(args, "=?") == 0) {
		print_line("+CPROT: 0"); /* OBEX */
		return AT_STATUS_OK;

	} else if (args[0] == '=') {
		pid_t p;
		int err;
		
		if (args[1] != '0' && args[2] != 0)
			return AT_STATUS_ERROR;

		err = start_obex_server(&p);
		if (err) {
			print_result_code("NO CARRIER", 3);
			return AT_STATUS_ERROR;

		} else {
			print_result_code("CONNECT", 1);
			waitpid(p, &err, 0);
			return AT_STATUS_OK;
		}
	}
	return AT_STATUS_ERROR;
}

static void handle_at_command(const char *cmd)
{
	static const struct {
		const char *cmd;
		int (*func)(const char*, size_t);
	} commands[] = {
		{"", &at_none},
		{"E0", &at_disable_echo},
		{"E1", &at_enable_echo},
		{"Q0", &at_disable_quiet},
		{"Q1", &at_enable_quiet},
		{"S3", &at_set_s3},
		{"S4", &at_set_s4},
		{"S5", &at_set_s5},
		{"V0", &at_disable_verbose},
		{"V1", &at_enable_verbose},
		{"Z", &at_reset},
		{"&F0", &at_reset},

		{"+GMI", &at_me_vendor},
		{"+GMM", &at_me_model},
		{"+GMR", &at_me_revision},

		{"+CGMI", &at_me_vendor},
		{"+CGMM", &at_me_model},
		{"+CGMR", &at_me_revision},
		{"+CPROT", &at_enter_protocol},

		{NULL, NULL} /* last entry */
	};

	int err = AT_STATUS_ERROR;
	size_t i = 0;
	size_t cmdlen = 0;

	debug_print("-> \"AT%s\"\n", buffer);

	for (; commands[i].cmd; ++i)
	{
		size_t len = strlen(commands[i].cmd);

		if (strncasecmp(commands[i].cmd, cmd, len) == 0 &&
		    (cmd[len] == 0 || cmd[len] == '=' || cmd[len] == '?'))
		{
			cmdlen = len;
			break;
		}
	}
	if (commands[i].func)
		err = commands[i].func(cmd, cmdlen);

	switch (err) {
	case AT_STATUS_OK:
		print_result_code("OK", 0);
		break;

	case AT_STATUS_ERROR:
		print_result_code("ERROR", 4);
		break;

	default:
		break;
	}
}

static int handle_input()
{
	size_t state = 0;

	for (;;) {
		ssize_t result;
		char buf[128];
		bool valid = true;
		
		result = read(STDIN_FILENO, buf, sizeof(buf));
		if (result < 0) {
			return -errno;
		} else 	if (result == 0) {
			return -EPIPE;
		}

		for (ssize_t i = 0; i < result; ++i) {
			if (state == 0) {
				if (buf[i] == 'A') {
					state = 1;
				} else {
					valid = false;
				}

			} else if (state == 1) {
				if (buf[i] == 'T') {
					state = 2;
					memset(buffer, 0, buflen);
					buflen = 0;

				} else 	if (buf[i] == '/') {
					handle_at_command(buffer);
					state = 0;

				} else {
					state = 0;
				}

			} else {
				if (buf[i] == s3) {
					handle_at_command(buffer);
					state = 0;

				} else if (buf[i] == s5) {
					if (buflen > 0)
						buffer[buflen--] = 0;
					else
						state = 1;

				} else {
					if (buflen+1 < sizeof(buffer))
						buffer[buflen++] = buf[i];
					else
						valid = false;
				}
			}

			if (valid && echo)
				(void)write(STDOUT_FILENO, &buf[i], 1);
		}
	}

	return 0;
}

static int open_tty_device(const char *device)
{
	int fd;

	fd = open(device, O_RDWR | O_NOCTTY, 0);
	if (fd == -1)
		return -errno;

	if (isatty(fd)) {
		if (tcgetattr(fd, &t) == -1)
			return -errno;
		cfmakeraw(&t);
		t.c_cc[VMIN] = 255;
		t.c_cc[VTIME] = 1;
	}

	fclose(stdin);
	dup2(fd, STDIN_FILENO);
	if (isatty(fd)) {
		(void)tcsetattr(STDIN_FILENO, 0, &t);
		(void)tcflush(STDIN_FILENO, TCIFLUSH);
	}
	stdin = fdopen(STDIN_FILENO, "r");

	fclose(stdout);
	dup2(fd, STDOUT_FILENO);
	if (isatty(fd)) {
		(void)tcsetattr(STDOUT_FILENO, 0, &t);
		(void)tcflush(STDOUT_FILENO, TCIFLUSH);
	}
	stdout = fdopen(STDOUT_FILENO, "w");

	close(fd);
	return 0;
}

static void print_disclaimer () {
	fprintf(stderr,
	        "ObexPushD AT wrapper " REVISION " Copyright (C) 2010 Hendrik Sattler\n"
		"This software comes with ABSOLUTELY NO WARRANTY.\n"
		"This is free software, and you are welcome to redistribute it\n"
		"under certain conditions.\n");
}

static void print_help (char* me) {
	print_disclaimer();
	printf("\n");
	printf("Usage: %s [<options>]\n", me);
	printf("\n"
	       "Options:\n"
	       " -S <device>    use device for I/O (default: stdin/stdout)\n"
	       " -d             enable debug output\n"
	       " -h             this help message\n"
	       " -v             show version\n");
	printf("\n"
	       "See manual page %s(1) for details.\n",me);
}

int main(int argc, char **argv)
{
	int c = 0;
	const char *device = NULL;
	bool debug = false;

	while (c != -1) {
		c = getopt(argc, argv, "S:dhv");
		switch (c) {
		case -1: /* processed all options, no error */
			break;

		case 'S': /* any TTY device */
			device = optarg;
			break;

		case 'd':
			debug = true;
			break;

		case 'h':
			print_help("obexpush_atd");
			exit(EXIT_SUCCESS);

		case 'v':
			printf("%s\n", REVISION);
			exit(EXIT_SUCCESS);

		default:
			break;
		}
	}

	if (!debug)
		fclose(stderr);

	print_disclaimer();
	if (device) {
		debug_print("Using device \"%s\"\n", device);
		if (open_tty_device(device)) {
			perror("Opening device failed");
			return EXIT_FAILURE;
		}
	} else {
		debug_print("Using %s\n", "stdin/stdout");
	}

	if (handle_input()) {
		perror("Reading from device failed");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
