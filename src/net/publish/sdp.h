#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#define BT_SDP_PROT_OBEX_PUSH (1 << 0)
#define BT_SDP_PROT_OBEX_FTP  (1 << 1)

void* bt_sdp_session_open (bdaddr_t* device, uint8_t channel, unsigned long protocols);
void bt_sdp_session_close (void* session_data, bdaddr_t* device);
