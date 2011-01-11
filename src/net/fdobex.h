#include "net.h"

#include <inttypes.h>
#ifndef HAS_SIGNALFD
#define HAS_SIGNALFD 1
#endif
#if HAS_SIGNALFD
#  include <sys/signalfd.h>
#  include <sys/signal.h>
#endif

struct fdobex_args {
	int in;
	int out;

	obex_ctrans_t ctrans;
#if HAS_SIGNALFD
	sigset_t sig_mask;
	int sig_fd;
#endif
	uint8_t *buf;
};

void fdobex_ctrans_set (obex_ctrans_t *ctrans);
