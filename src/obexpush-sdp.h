#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

sdp_session_t* bt_sdp_session_open (bdaddr_t* device, uint8_t channel);

