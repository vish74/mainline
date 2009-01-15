#include <stdlib.h>

static const char* action_script = NULL;

void set_io_script (const char *script)
{
  action_script = script;
}

const char * get_io_script (void)
{
  return action_script;
}
