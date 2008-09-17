#include <sys/types.h>

#define IO_FLAG_READ  (1 << 0)
#define IO_FLAG_WRITE (1 << 1)
int io_script_open (file_data_t* data, char* script, char** args);
int io_file_open (file_data_t* data, unsigned long io_flags);
int io_close (file_data_t* data);

pid_t pipe_open (const char* command, char** args, int client_fds[2]);
void pipe_close (int client_fds[2]);
