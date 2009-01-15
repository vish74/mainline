#include <inttypes.h>
#include <stdlib.h>

/* count the number of used elements (NOT characters)
 * This works independent of byte order.
 */
size_t ucs2len (/*@null@*/const uint16_t* s);
#define utf8len(s) ((s)? strlen((char*)(s)): 0)
#define utf16len(s) ucs2len(s)


/* convert to network byte order and back
 */
void ucs2_ntoh (uint16_t* s, size_t len);
void ucs2_hton (uint16_t* s, size_t len);


/* Count the unicode characters
 * (does _not_ check for validity)
 */
size_t utf8count(const uint8_t* s);
/* s MUST be in host byte order */
size_t utf16count(const uint16_t* s);


/* convert between UTF-8 and UTF-16
 * c values MUST be in host byte order
 * returned pointer must be free'd and is
 *          in host byte order
 */
uint8_t* utf16to8 (const uint16_t* c);
uint16_t* utf8to16 (const uint8_t* c);
