#include <openobex/obex.h>

void obex_action_connect (obex_t* handle, obex_object_t* obj, int event);
void obex_action_disconnect (obex_t* handle, obex_object_t* obj, int event);
void obex_action_put (obex_t* handle, obex_object_t* obj, int event);
void obex_action_get (obex_t* handle, obex_object_t* obj, int event);
void obex_action_setpath (obex_t* handle, obex_object_t* obj, int event);
