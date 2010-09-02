int obex_object_headers (file_data_t* data, obex_object_t* obj);

extern const struct obex_target_event_ops obex_action_connect;
extern const struct obex_target_event_ops obex_action_disconnect;
extern const struct obex_target_event_ops obex_action_put;
extern const struct obex_target_event_ops obex_action_ftp_put;
extern const struct obex_target_event_ops obex_action_get;
extern const struct obex_target_event_ops obex_action_setpath;

extern const struct obex_target_ops obex_target_ops_opp;
extern const struct obex_target_ops obex_target_ops_ftp;
