#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elfload.h"
#include "elfload_dlfcn.h"
#include "elfload_exec.h"

#define INFO(args...) //printf(args)
#define ERR(args...) fprintf(stderr, args)

#define STRINGIFY(x) #x
#define STRINGIT(x) STRINGIFY(x)

char XSYMBOL[XSYMBOL_SIZE];

const char *
hook_libs(const char *nm)
{
    static const char *libs[][2] = {
#ifdef __APPLE__
        { "librt.so.1",         NULL },
        { "libc.so.6",          "libhost_/usr/lib/libSystem.B.dylib" },
        { "libdl.so.2",         "libhost_/usr/lib/libdl.dylib" },
        { "libgcc_s.so.1",      "libhost_/usr/lib/libgcc_s.1.dylib" },
        { "libm.so.6",          "libhost_/usr/lib/libm.dylib" },
        { "libpthread.so.0",    "libhost_/usr/lib/libpthread.dylib" },
        { "libstdc++.so.6",     "libhost_/usr/lib/libstdc++.6.dylib" },
        { "libSomething.so",    "libhost_../libSomething.dylib" },
#else
        { "librt.so.1",         "libhost_librt.so.1" },
        { "libc.so.6",          "libhost_libc.so.6" },
        { "libdl.so.2",         "libhost_libdl.so.2" },
        { "libgcc_s.so.1",      "libhost_libgcc_s.so.1" },
        { "libm.so.6",          "libhost_libm.so.6" },
        { "libpthread.so.0",    "libhost_libpthread.so.0" },
        { "libstdc++.so.6",     "libhost_libstdc++.so.6" },
#endif
        { NULL, NULL }
    };
    unsigned i;
    for (i = 0; libs[i][0]; i++) {
        if (!strcmp(nm, libs[i][0])) {
            return libs[i][1];
        }
    }
    return nm;
}

#ifdef WEIRD_FUNC_CALL
struct a {
    int rv;
    int tmp[2];
};

struct b {
    int parm[32];
};

extern int (*weirdo)(struct b b);

static struct a
my_weirdo(struct b b)
{
    struct a a;
//    fprintf(stderr, "weirdo(0x%x, 0x%x, 0x%x, ...)", b.parm[0], b.parm[1], b.parm[2]);
    a.rv = -1;//weirdo(b);
//    fprintf(stderr, " -> 0x%x\n", a.rv);
    return a; /* XXX ret 4 */
}

static struct a (*new_weirdo)(struct b b) = my_weirdo;
#endif

extern char cxa_throw[];
extern void *eh_frame;

const char *
hook_syms(const char *nm, void **p)
{
    // XXX elfload_dl* API is not quite correct, because
    // XXX it won't call ctors/dtors but will do for now
    static const char *syms[][3] = {
        { "dlopen",             NULL,           (char *)(uintptr_t)elfload_dlopen },
        { "dlsym",              NULL,           (char *)(uintptr_t)elfload_dlsym },
        { "dlclose",            NULL,           (char *)(uintptr_t)elfload_dlclose },
        { "dlerror",            NULL,           (char *)(uintptr_t)elfload_dlerror },
        { "__cxa_throw",        NULL,           (char *)(uintptr_t)cxa_throw },
#ifdef __APPLE__
        { "_Znwj",              "_Znwm",        NULL },
        { "__errno_location",   "__error",      NULL },
#ifdef WEIRD_FUNC_CALL
        { "weirdo",             NULL,           (char *)&new_weirdo },
#endif
#endif
        { NULL, NULL },
    };
    unsigned i;
    *p = NULL;
    for (i = 0; syms[i][0]; i++) {
        if (!strcmp(nm, syms[i][0])) {
            if (syms[i][2]) {
                *p = (void *)syms[i][2];
                return NULL;
            }
            return syms[i][1];
        }
    }
    return nm;
}

static char *
build_path(void)
{
    static char buf[4096];
    Dl_info info;
    int rv = dladdr((void *)(uintptr_t)build_path, &info);
    if (rv && info.dli_fname) {
        size_t len;
        const char *p = strrchr(info.dli_fname, '.');
        if (p && p > info.dli_fname && (/*p[-1] != '/' ||*/ p[1] != '/')) {
            len = p - info.dli_fname;
        } else {
            len = strlen(info.dli_fname);
        }
        if (len + 1 + sizeof("so") > sizeof(buf)) {
            return NULL;
        }
        memcpy(buf, info.dli_fname, len);
        buf[len++] = '.';
        strcpy(buf + len, "so");
        return buf;
    }
    return NULL;
}

void __attribute__((constructor))
initme(void)
{
    void *sym;
    struct ELF_File *f;
    char *dir, *fil, *path = build_path();

    if (!path) {
        return;
    }
    INFO("load: %s\n", path);

    fil = strrchr(path, '/');
    if (!fil) {
        dir = "";
        fil = path;
    } else {
        *fil++ = '\0';
        dir = path;
    }

    elfload_dlinstdir = dir;

    /* load them all in */
    f = loadELF(fil, dir, 0);

    if (!f) {
        ERR("Failed to load %s.\n", fil);
        return;
    }
    eh_frame = f->eh_frame;

    /* relocate them */
    relocateELFs();

    /* initialize .so files */
    initELF(NULL);

    /* do our thing */
    sym = elfload_dlsym(f, STRINGIT(XSYMBOL));
    if (sym) {
        memcpy(XSYMBOL, sym, sizeof(XSYMBOL));
    }

    INFO("base: %p\n", (void *)f->loc);
}

void __attribute__((destructor))
finime(void)
{
    unloadELFs();
    INFO("unload\n");
}

#ifdef HAVE_MAIN
int
main(void)
{
    void *sym;
    sym = elfload_dlsym(NULL, "square");
    if (sym) {
        printf("square = %d\n", ((int (*)(int))(uintptr_t)sym)(3));
    }
    sym = elfload_dlsym(NULL, "hello");
    if (sym) {
        printf("count = %d\n", ((int (*)(char *))(uintptr_t)sym)("world"));
    }
    sym = elfload_dlsym(NULL, "exposed");
    if (sym) {
        printf("exposed = %d\n", *(int *)sym);
    }
    sym = elfload_dlsym(NULL, "plus");
    if (sym) {
        printf("plus = %d\n", ((int (*)(int))(uintptr_t)sym)(4));
    }
    return 0;
}
#endif
