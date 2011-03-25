
#include <inttypes.h>

int check_name (uint8_t *name);
int check_type (uint8_t *type);
int check_wrap_ucs2 (uint16_t *name, int (*func)(uint8_t*));
