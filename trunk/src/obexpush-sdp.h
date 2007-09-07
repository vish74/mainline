#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

sdp_session_t* bt_sdp_session_open (uint8_t channel);
int bt_sdp_session_close (sdp_session_t* session);
