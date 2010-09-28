#include <sys/types.h>

int pipe_open (const char* command, char** args, int client_fds[2], pid_t *pid);
void pipe_close (int client_fds[2]);
