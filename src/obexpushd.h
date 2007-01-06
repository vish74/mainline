#include <openobex/obex.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef enum {
	INTF_BLUETOOTH = 0,
	INTF_IRDA = 1,
	INTF_INET = 2,
} intf_t;

typedef struct {
	intf_t intf;
} listener_data_t;

/* private data for a client connection */
typedef struct {
	intf_t intf;
	unsigned int id;
	unsigned int count;

	uint16_t* name;
	char* type;
	size_t length;
	time_t time;

	FILE* out;
	pid_t child;
	uint8_t buffer[1000];

	/* auth */
	uint8_t nonce[16];
	int auth_success;
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
