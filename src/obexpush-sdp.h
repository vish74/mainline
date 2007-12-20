#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

sdp_session_t* bt_sdp_session_open (bdaddr_t* device, uint8_t channel);
void bt_sdp_session_close (sdp_session_t* session, bdaddr_t* device, uint8_t channel);
