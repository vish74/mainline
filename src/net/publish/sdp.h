#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

void* bt_sdp_session_open (bdaddr_t* device, uint8_t channel);
void bt_sdp_session_close (void* session_data, bdaddr_t* device);
