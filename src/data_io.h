#include <sys/types.h>

int file_open (char* name,
	       int mode);

int pipe_open (const char* command,
	       char** args,
	       int mode,
	       /*out*/ pid_t* pid);
