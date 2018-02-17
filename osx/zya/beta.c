#define IMPORT_PRIVATE(anchor, offset, alias) \
    void *alias(void *a, void *b, void *c, void *d, void *e, void *f) \
    { \
        extern char anchor[]; \
        return ((void *(*)())(anchor + offset))(a, b, c, d, e, f); \
    }

IMPORT_PRIVATE(create_strlit, 0x20c0, cfgopt_t__apply)

/*
 * function wrapping: this is slightly different than just aliasing, because we need
 * to provide BOTH symbols *and* rely on the other library for backend implementation
 */

#include <stdio.h>

int zya936(char **a, long b);

int
run_plugin(char **a, long b)
{
    if (a) {
        printf("%s: %s\n", __func__, a[6]);
    }
    return zya936(a, b);
}

const struct {
    void *repl;
    void *orig;
} interposers[] __attribute__((section("__DATA, __interpose"))) = {
    { .repl = (void *)run_plugin, .orig = (void *)zya936 },
};
