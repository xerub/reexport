#ifndef LIB_H
#define LIB_H

#include <stdbool.h>
#include <stddef.h> /* size_t, NULL, etc. */
#include <stdint.h>

void *create_strlit(); /* anchor */
#define A(offset) ((uintptr_t)create_strlit + (offset) - 0x3dec0)

int _patch_dword(uintptr_t dest, unsigned int value);

#ifndef DISABLE_API

#define get_dirty_infos         zya323

unsigned int get_dirty_infos(void);

#endif
#endif
