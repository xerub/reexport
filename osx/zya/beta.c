static int unused __attribute__((unused));

#if 0
/*
 * function wrapping: this is slightly different than just aliasing, because we need
 * to provide BOTH symbols *and* rely on the first library for backend implementation
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
#endif
