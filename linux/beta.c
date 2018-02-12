extern int x;

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

IMPORT(alpha, beta)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <stdio.h>

#define COPY(sym) \
    do { \
        void *that = dlsym(RTLD_NEXT, #sym); \
        /*if (that) { sym = *(typeof(sym) *)that; break; }*/ \
        /*if (that) { memcpy(&sym, that, sizeof(sym)); break; }*/ \
        void *this = dlsym(RTLD_DEFAULT, #sym); \
        if (this && that) { \
            Dl_info info; \
            ElfW(Sym) *extra_info = NULL; \
            int rv = dladdr1(that, &info, (void **)&extra_info, RTLD_DL_SYMENT); \
            if (rv && extra_info && sizeof(sym) >= extra_info->st_size) { \
                memcpy(this, that, extra_info->st_size); \
            } \
        } \
    } while (0)

static void __attribute__((constructor))
initme(void)
{
    /* pull in x -- we need to link this with a COPY reloc to x */
    printf("here B: x: *%p = %u\n", (void *)&x, x);
    /* however, in certain circumstances, the linker did not COPY the value. do it now
     * NB: if the next lib has constructors that rely on these values being != 0, we are probably fucked...
     */
    COPY(x);
}

int
main(void)
{
    return 0;
}
