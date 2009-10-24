#include <unistd.h>
#include <inttypes.h>

struct MD5Context {
	uint32_t buf[4];
	uint32_t bytes[2];
	uint32_t in[16];
};

void MD5Init(struct MD5Context *ctx);
void MD5Update(struct MD5Context *ctx, uint8_t const *buf, size_t len);
void MD5Final(uint8_t digest[16], struct MD5Context *ctx);

/* all-in-one */
void MD5(uint8_t* dest, uint8_t const *orig, size_t len);
