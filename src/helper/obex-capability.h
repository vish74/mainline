#include <stdio.h>

struct obex_caps_general {
	char* vendor;
	char* model;
};

struct obex_capability {
	struct obex_caps_general general;
};

int obex_capability (FILE* fd, struct obex_capability* caps);
