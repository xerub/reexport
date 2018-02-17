#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#define DISABLE_API
#include "lib.h"

#define IMPORT_PRIVATE(offset, alias) \
    void *alias(void *a, void *b, void *c, void *d, void *e, void *f) \
    { \
        return ((void *(*)())A(offset))(a, b, c, d, e, f); \
    }

IMPORT_PRIVATE(0x009730, cfgopt_t__apply)

int __attribute__((visibility("hidden")))
_patch_dword(uintptr_t dest, unsigned int value)
{
    void *base = (void *)(dest & ~0xFFF);
    int rv = mprotect(base, 0x1000, PROT_READ | PROT_WRITE);
    if (rv == 0) {
        *(unsigned int *)dest = value;
        rv = mprotect(base, 0x1000, PROT_READ | PROT_EXEC);
    }
    return rv;
}

static void __attribute__((constructor))
init(void)
{
}
