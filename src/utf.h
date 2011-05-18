#include <inttypes.h>
#include <stdlib.h>

/* count the number of used elements (NOT characters)
 * This works independent of byte order.
 */
size_t utf8len (const uint8_t* s);
size_t ucs2len (const uint16_t* s);

/* copy the UCS-2 string to a new allocated one
 */
uint16_t* ucs2dup (const uint16_t* s);

/* convert to network byte order and back
 */
void ucs2_ntoh (uint16_t* s, size_t len);
void ucs2_hton (uint16_t* s, size_t len);

/* Count the unicode characters
 * (does _not_ check for validity)
 */
size_t utf8count(const uint8_t* s);
/* s MUST be in host byte order */
size_t ucs2count(const uint16_t* s);

/* Sadly, OBEX doesn't use UTF-16 but UCS-2,
 * these functions convert to/from UTF-8.
 * UCS-2 values MUST be in host byte order.
 * returned pointer must be free'd and is
 *          in host byte order
 */
uint8_t* ucs2_to_utf8 (const uint16_t* c);
uint16_t* utf8_to_ucs2 (const uint8_t* c);
