#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* private data for a client connection */
typedef struct {
	unsigned int id;
	unsigned int count;

	uint16_t* name;
	char* type;
	size_t length;
	time_t time;

	FILE* out;
	pid_t child;
	uint8_t buffer[1000];

	struct net_data* net_data;
} file_data_t;

/* file input */
int put_open (obex_t* handle, char* script);
int put_write (obex_t* handle, const uint8_t* buf, int len);
int put_close (obex_t* handle, int wait);
int put_revert (obex_t* handle);

/* file output */
int get_open (obex_t* handle, char* script);
int get_read (obex_t* handle, uint8_t* buf, size_t size);
int get_close (obex_t* handle, int wait);

int check_name (uint16_t* name);
int check_type (char* type);
