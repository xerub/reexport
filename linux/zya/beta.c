extern char zya45[408];
extern char zya60;
extern void *zya99;
extern long zya144;
extern char zya224;
extern char zya597[280];
extern int zya679;
extern char zya787[144];
extern long zya935;
extern char zya1094;

#ifdef SIMPLE_JMP
#define IMPORT(import, alias) \
    extern void *import(); \
    void *alias() { return import(); } /* create code trampoline */
#else /* IFUNC */
#define IMPORT(import, alias) \
    extern void *import(); \
    static void *(*resolve_##alias(void))() { return import; } \
    void *alias() __attribute__((ifunc("resolve_" #alias)));
#endif /* IFUNC */

IMPORT(zya146, decode_insn)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <stdio.h>

#define COPY(sym) \
    do { \
        void *that = dlsym(RTLD_NEXT, #sym); \
        if (that) { \
            memcpy(&sym, that, sizeof(sym)); \
        } \
    } while (0)

static void __attribute__((constructor))
initme(void)
{
    /* pull in data imports, yet this code is not executed. magic, eh? */
    COPY(zya45);
    COPY(zya60);
    COPY(zya99);
    COPY(zya144);
    COPY(zya224);
    COPY(zya597);
    COPY(zya679);
    COPY(zya787);
    COPY(zya935);
    COPY(zya1094);
    __builtin_trap();
}

void
_start(void)
{
    __builtin_trap();
}

#if 0
/*
 * function wrapping: this is slightly different than just aliasing, because we need
 * to provide BOTH symbols *and* rely on the first library for backend implementation
 */

#include <stdio.h>

int
run_plugin(char **a, long b)
{
    static unsigned long func = 0;
    if (!func) {
        func = (unsigned long)dlsym(RTLD_NEXT, "zya936");
    }
    if (a) {
        printf("%s: %s\n", __func__, a[6]);
    }
    return ((typeof(run_plugin) *)func)(a, b);
}
int zya936(char **a, long b) __attribute__((alias("run_plugin")));
#endif
