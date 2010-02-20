int obex_object_headers (file_data_t* data, obex_object_t* obj);

void obex_action_connect (file_data_t* data, obex_object_t* obj, int event);
void obex_action_disconnect (file_data_t* data, obex_object_t* obj, int event);
void obex_action_put (file_data_t* data, obex_object_t* obj, int event);
void obex_action_get (file_data_t* data, obex_object_t* obj, int event);
void obex_action_setpath (file_data_t* data, obex_object_t* obj, int event);
