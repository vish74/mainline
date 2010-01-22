#include <stdio.h>

#define OFL_FLAG_PARENT (1 << 0) /* show parent folder indicator */
#define OFL_FLAG_HIDDEN (1 << 1) /* also list hidden files/directories */
#define OFL_FLAG_TIMES  (1 << 2) /* show time attributes */
#define OFL_FLAG_PERMS  (1 << 3) /* show permission attributes */
#define OFL_FLAG_OWNER  (1 << 4) /* show file owner attribute */
#define OFL_FLAG_GROUP  (1 << 5) /* show file group attribute */
#define OFL_FLAG_KEEP   (1 << 6) /* keep files: writing existing file is not supported */
#define OFL_FLAG_NODEL  (1 << 7) /* deleting is not supported */

/** write the OBEX folder listing
 * @param fd    the output
 * @param name  name of file or directory
 * @param flags flags that trigger the output of various elements or attributes
 */
int obex_folder_listing (FILE* fd, char* name, int flags);
