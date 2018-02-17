#include <termios.h>
#include <unistd.h>
#include "lib.h"

bool
is_refresh_requested(unsigned int mask)
{
    return (get_dirty_infos() & mask) != 0;
}
