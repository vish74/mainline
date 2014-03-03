#include <stdio.h>
#include <inttypes.h>
#if __STDC_VERSION__ >= 199901L
#include <stdbool.h>
#else
#define bool unsigned int
#define true 1
#define false 0
#endif

struct obex_caps_version {
	char* version;
	char* date;
};

struct obex_caps_limit {
	unsigned long size_max; /* ULONG_MAX for not limit */
	unsigned long namelen_max; /* ULONG_MAX for not limit */
};

struct obex_caps_ext {
	char* name;
	char** value; /* list */
	unsigned int value_count;
};

struct obex_caps_obj {
	/* type or at least one ext must be defined */
	char* type;
	char** name_ext; /* list */
	unsigned int name_ext_count;
	unsigned long* size;
	struct obex_caps_ext* ext; /* list */
	unsigned int ext_count;
};

struct obex_caps_access {
	char* protocol;
	char* endpoint;
	char* target;
	struct obex_caps_ext* ext; /* list */
	unsigned int ext_count;
};

struct obex_caps_mem {
	char* type;
	char* location;
	unsigned long free;
	unsigned long used;
	struct obex_caps_limit file;
	struct obex_caps_limit folder;
	unsigned int flags;
#define OBEX_CAPS_MEM_SHARED    (1 << 0)
#define OBEX_CAPS_MEM_CASESENSE (1 << 1)
	struct obex_caps_ext* ext; /* list */
	unsigned int ext_count;
};

struct obex_caps_general {
	char* vendor;
	char* model;
	char* serial;
	char* oem;
	struct obex_caps_version* sw;
	struct obex_caps_version* fw;
	struct obex_caps_version* hw;
	char lang[2+1];
	struct obex_caps_mem* mem; /* list */
	unsigned int mem_count;
	struct obex_caps_ext* ext; /* list */
	unsigned int ext_count;
};

struct obex_caps_inbox {
	struct obex_caps_obj* obj; /* list */
	unsigned int obj_count;
	struct obex_caps_ext* ext; /* list */
	unsigned int ext_count;
};

struct obex_caps_uuid {
	enum {
		OBEX_CAPS_UUID_ASCII,
		OBEX_CAPS_UUID_BINARY,
	} type;
	uint8_t data[16];
};
#define OBEX_UUID_FBS \
	{ 0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, \
	0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09 }
#define OBEX_UUID_IRMC \
	{ 'I', 'R', 'M', 'C', '-', 'S', 'Y', 'N', 'C' }

struct obex_caps_service {
	/* name or uuid must be defined */
	char* name;
	struct obex_caps_uuid* uuid;
	char* version;
	struct obex_caps_obj* obj; /* list */
	unsigned int obj_count;
	struct obex_caps_access* access; /* list */
	unsigned int access_count;
	struct obex_caps_ext* ext; /* list */
	unsigned int ext_count;
};

struct obex_capability {
	char* charset;
	struct obex_caps_general general;
	struct obex_caps_inbox* inbox;
	struct obex_caps_service* service;
};

int obex_capability (FILE* fd, struct obex_capability* caps);
