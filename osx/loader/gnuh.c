#include <string.h>
#include "elfload.h"
#include "elfload_dlfcn.h"

unsigned long
gnu_hash(const char *name)
{
    const unsigned char *uname = (const unsigned char *)name;
    unsigned long h = 5381;
    unsigned char c;
    while ((c = *uname++) != '\0') {
        h = (h << 5) + h + c;
    }
    return h & 0xffffffff;
}

/* Different architectures have different symbol structure size.
 * Those actually should be selected depending on input binary's ELFCLASS,
 * but for simplicity I've left them as typedefs and defines.
 */
#ifdef __LP64__
typedef uint64_t bloom_el_t;
#define ELFCLASS_BITS 64
#else
typedef uint32_t bloom_el_t;
#define ELFCLASS_BITS 32
#endif

void *
gnu_lookup(const char *name, struct ELF_File *f, int inlocal, ElfNative_Sym **syminto)
{
    const uint32_t *hashtab = f->gnuhash;
    const uint32_t namehash = gnu_hash(name);

    const uint32_t nbuckets = hashtab[0];
    const uint32_t symoffset = hashtab[1];
    const uint32_t bloom_size = hashtab[2];
    const uint32_t bloom_shift = hashtab[3];
    const bloom_el_t *bloom = (void *)&hashtab[4];
    const uint32_t *buckets = (void *)&bloom[bloom_size];
    const uint32_t *chain = &buckets[nbuckets];

    bloom_el_t word = bloom[(namehash / ELFCLASS_BITS) % bloom_size];
    bloom_el_t mask = 0
        | (bloom_el_t)1 << (namehash % ELFCLASS_BITS)
        | (bloom_el_t)1 << ((namehash >> bloom_shift) % ELFCLASS_BITS);

    /* If at least one bit is not set, a symbol is surely missing. */
    if ((word & mask) != mask) {
        return NULL;
    }

    uint32_t symix = buckets[namehash % nbuckets];
    if (symix < symoffset) {
        return NULL;
    }

    /* Loop through the chain. */
    while (8) {
        const char *symname = f->strtab + f->symtab[symix].st_name;
        const uint32_t hash = chain[symix - symoffset];

        if ((namehash | 1) == (hash | 1) && strcmp(name, symname) == 0) {
            ElfNative_Sym *sym = &(f->symtab[symix]);
            if ((inlocal || ELFNATIVE_ST_BIND(sym->st_info) != STB_LOCAL) && sym->st_shndx != SHN_UNDEF) {
                if (syminto != NULL) {
                    *syminto = sym;
                }
                return (void *)(sym->st_value + f->offset);
            }
            return NULL;
        }

        /* Chain ends with an element with the lowest bit set to 1. */
        if (hash & 1) {
            break;
        }

        symix++;
    }

    return NULL;
}
