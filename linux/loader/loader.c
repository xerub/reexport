/*
 *  dylib loader
 *
 *  Copyright (c) 2015, 2016, 2018 xerub
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/fat.h>

#define STRINGIFY(x) #x
#define UNDERSCORE(x) "_" STRINGIFY(x)

#define INFO(args...) //printf(args)
#define ERR(args...) fprintf(stderr, args)

#define round_page(size) ((size + 0xFFF) & ~0xFFF)

#define IS64(image) (*(uint8_t *)(image) & 1)

#ifdef __LP64__
static const uint8_t kernel[] = {
    0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00
};
#else
static const uint8_t kernel[] = {
    0xce, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00
};
#endif

/* fat ***********************************************************************/

struct macho {
    int fd;
    size_t off, end;
};

static int
mclose(struct macho *macho)
{
    int rv = -1;
    if (macho) {
        rv = close(macho->fd);
        free(macho);
    }
    return rv;
}

static ssize_t
mread(struct macho *macho, void *buf, size_t count, off_t offset)
{
    size_t len;
    size_t off;
    if (!macho) {
        return -1;
    }
    off = offset + macho->off;
    if (off < macho->off) {
        return -1;
    }
    if (off >= macho->end) {
        return 0;
    }
    len = macho->end - off;
    if (len > count) {
        len = count;
    }
    return pread(macho->fd, buf, len, off);
}

static struct macho *
mopen(const char *filename, int mode, const struct mach_header *target)
{
    int rv;
    int fd;
    size_t size;
    unsigned i, n;
    struct stat st;
    struct fat_header fat_buf;
    struct mach_header hdr;
    struct macho *macho;

    macho = malloc(sizeof(struct macho));
    if (macho == NULL) {
        return NULL;
    }

    fd = open(filename, mode);
    if (fd < 0) {
        free(macho);
        return NULL;
    }
    macho->fd = fd;

    rv = fstat(fd, &st);
    if (rv) {
        mclose(macho);
        return NULL;
    }

    size = read(fd, &fat_buf, sizeof(fat_buf));
    if (size != sizeof(fat_buf)) {
        mclose(macho);
        return NULL;
    }

    if (fat_buf.magic != FAT_CIGAM) {
        if (fat_buf.magic == target->magic && (cpu_type_t)fat_buf.nfat_arch == target->cputype) {
            size = read(fd, &n, sizeof(n));
            if (size == sizeof(n) && (cpu_subtype_t)n <= target->cpusubtype) {
                macho->off = 0;
                macho->end = st.st_size;
                return macho;
            }
        }
        mclose(macho);
        return NULL;
    }

    n = __builtin_bswap32(fat_buf.nfat_arch);
    for (i = 0; i < n; i++) {
        size_t off, end;
        struct fat_arch arch_buf;
        size = pread(fd, &arch_buf, sizeof(arch_buf), sizeof(fat_buf) + i * sizeof(arch_buf));
        if (size != sizeof(arch_buf)) {
            break;
        }
        off = __builtin_bswap32(arch_buf.offset);
        end = off + __builtin_bswap32(arch_buf.size);
        if (end < off || (off_t)end > st.st_size) {
            break;
        }
        macho->off = off;
        macho->end = end;
        size = mread(macho, &hdr, sizeof(hdr), 0);
        if (size != sizeof(hdr)) {
            break;
        }
        if (hdr.magic == target->magic && hdr.cputype == target->cputype && hdr.cpusubtype <= target->cpusubtype) {
            return macho;
        }
    }

    mclose(macho);
    return NULL;
}

/* the real mccoy ************************************************************/

static long __stack_chk_guard[8] = {0, 0, 10, 255, 0, 0, 0, 0};
extern char _DefaultRuneLocale[];
static int num_ctors;
static uintptr_t *ctors;
static int num_dtors;
static uintptr_t *dtors;
static uintptr_t the_ptr;
char XSYMBOL[XSYMBOL_SIZE];

static void
dyld_stub_binder(void)
{
    assert(0);
}

extern char cxa_throw[];
extern void *eh_frame;

static uintptr_t
solver(const char *symbol)
{
    static const struct {
        const char *osx;
        const void *lin;
        int dynamic;
    } syms[] = {
        { "___cxa_throw", cxa_throw, 0 },
        { "dyld_stub_binder", (void *)(uintptr_t)dyld_stub_binder, 0 },
        { "__DefaultRuneLocale", _DefaultRuneLocale, 0 },
        { "___stack_chk_guard", __stack_chk_guard, 0 },
        { "___tolower", "_tolower", 1 },
        { "___toupper", "_toupper", 1 },
        { NULL, NULL, 0 }
    };
    unsigned i;
    uintptr_t addr = 0;
    for (i = 0; syms[i].osx; i++) {
        if (!strcmp(syms[i].osx, symbol)) {
            if (syms[i].dynamic) {
                symbol = syms[i].lin;
                break;
            }
            addr = (uintptr_t)syms[i].lin;
            break;
        }
    }
    if (!addr) {
        addr = (uintptr_t)dlsym(RTLD_DEFAULT, symbol + 1);
    }
    INFO("solve: %s -> 0x%zx\n", symbol, addr);
    return addr;
}

static void
preload(const char *dependency)
{
    static const struct {
        const char *osx;
        const char *lin;
    } libs[] = {
        { "/usr/lib/libSystem.B.dylib", NULL },
        { "/usr/lib/libiconv.2.dylib", NULL },
        { "/usr/lib/libstdc++.6.dylib", "libstdc++.so.6" },
        { "/usr/lib/libgcc_s.1.dylib", "libgcc_s.so.1" },
        { NULL, NULL }
    };
    unsigned i;
    INFO("dlopen(%s)", dependency);
    for (i = 0; libs[i].osx; i++) {
        if (!strcmp(libs[i].osx, dependency)) {
            if (libs[i].lin) {
                void *h = dlopen(libs[i].lin, RTLD_GLOBAL | RTLD_LAZY);
                INFO(" -> %s -> %p", libs[i].lin, h);
                (void)h;
            }
            break;
        }
    }
    INFO("\n");
}

static uintptr_t
read_uleb128(const uint8_t **q, const uint8_t *end)
{
    const uint8_t *p = *q;
    uint64_t result = 0;
    int bit = 0;
    do {
        uint64_t slice;

        if (p == end) {
            errx(1, "malformed uleb128 extends beyond trie");
        }

        slice = *p & 0x7f;

        if (bit >= 64 || slice << bit >> bit != slice) {
            errx(1, "uleb128 too big for 64-bits");
        } else {
            result |= (slice << bit);
            bit += 7;
        }
    } while (*p++ & 0x80);
    *q = p;
    return result;
}

static intptr_t
read_sleb128(const uint8_t **q, const uint8_t *end)
{
    const uint8_t *p = *q;
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (p == end) {
            errx(1, "malformed sleb128");
        }
        byte = *p++;
        result |= ((int64_t)(byte & 0x7f)) << bit;
        bit += 7;
    } while (byte & 0x80);
    if (byte & 0x40) {
        result |= (-1LL) << bit;
    }
    *q = p;
    return result;
}

#define segActualLoadAddress(i) segments[(i) * 2]
#define segActualEndAddress(i) segments[(i) * 2 + 1]

static void
bindAt(void *context, uintptr_t addr, uint8_t type, const char* symbolName, uint8_t symbolFlags, int64_t addend, long libraryOrdinal)
{
    INFO("#import: 0x%zx %s\n", addr, symbolName);
    (void)(context && addr && type && symbolName && symbolFlags && addend && libraryOrdinal);
}

static void
do_import(const uint8_t *buf, uint32_t bind_off, uint32_t bind_size, const uintptr_t *segments, int n, void *context, int lazy)
{
	uint32_t i;
	uint8_t type = lazy;
	int segmentIndex = 0;
	uintptr_t address = segActualLoadAddress(0);
	uintptr_t segmentEndAddress = segActualEndAddress(0);
	const char* symbolName = NULL;
	uint8_t symboFlags = 0;
	long libraryOrdinal = 0;
	intptr_t addend = 0;
	uintptr_t count;
	uintptr_t skip;
	const uint8_t* const start = buf + bind_off;
	const uint8_t* const end = &start[bind_size];
	const uint8_t* p = start;
	int done = 0;
	while ( !done && (p < end) ) {
		uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
		uint8_t opcode = *p & BIND_OPCODE_MASK;
		++p;
		switch (opcode) {
			case BIND_OPCODE_DONE:
				if (!lazy) done = 1;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
				libraryOrdinal = immediate;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
				libraryOrdinal = read_uleb128(&p, end);
				break;
			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
				// the special ordinals are negative numbers
				if ( immediate == 0 )
					libraryOrdinal = 0;
				else {
					int8_t signExtended = BIND_OPCODE_MASK | immediate;
					libraryOrdinal = signExtended;
				}
				break;
			case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
				symbolName = (char*)p;
				symboFlags = immediate;
				while (*p != '\0')
					++p;
				++p;
				break;
			case BIND_OPCODE_SET_TYPE_IMM:
				type = immediate;
				break;
			case BIND_OPCODE_SET_ADDEND_SLEB:
				addend = read_sleb128(&p, end);
				break;
			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				segmentIndex = immediate;
				if ( segmentIndex >= n )
					errx(1, "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (%d)\n", 
							segmentIndex, n);
				address = segActualLoadAddress(segmentIndex) + read_uleb128(&p, end);
				segmentEndAddress = segActualEndAddress(segmentIndex);
				break;
			case BIND_OPCODE_ADD_ADDR_ULEB:
				address += read_uleb128(&p, end);
				break;
			case BIND_OPCODE_DO_BIND:
				if ( address >= segmentEndAddress ) 
					errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
				bindAt(context, address, type, symbolName, symboFlags, addend, libraryOrdinal);
				address += sizeof(intptr_t);
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
				if ( address >= segmentEndAddress ) 
					errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
				bindAt(context, address, type, symbolName, symboFlags, addend, libraryOrdinal);
				address += read_uleb128(&p, end) + sizeof(intptr_t);
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				if ( address >= segmentEndAddress ) 
					errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
				bindAt(context, address, type, symbolName, symboFlags, addend, libraryOrdinal);
				address += immediate*sizeof(intptr_t) + sizeof(intptr_t);
				break;
			case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
				count = read_uleb128(&p, end);
				skip = read_uleb128(&p, end);
				for (i=0; i < count; ++i) {
					if ( address >= segmentEndAddress ) 
						errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
					bindAt(context, address, type, symbolName, symboFlags, addend, libraryOrdinal);
					address += skip + sizeof(intptr_t);
				}
				break;
			default:
				errx(1, "bad bind opcode %d in bind info", *p);
		}
	}
}

static void
rebaseAt(void *context, uintptr_t addr, uintptr_t slide, uint8_t type)
{
    *(uintptr_t *)addr += slide;
    (void)(context && type);
}

static void
do_rebase(const uint8_t *buf, uint32_t rebase_off, uint32_t rebase_size, const uintptr_t *segments, int n, void *context)
{
	unsigned fgTotalRebaseFixups = 0;
	const uintptr_t slide = *(uintptr_t *)context;
	const uint8_t* const start = buf + rebase_off;
	const uint8_t* const end = &start[rebase_size];
	const uint8_t* p = start;

	uint8_t type = 0;
	int segmentIndex = 0;
	uintptr_t address = segActualLoadAddress(0);
	uintptr_t segmentEndAddress = segActualEndAddress(0);
	uintptr_t count;
	uintptr_t skip;
	int done = 0;
	while ( !done && (p < end) ) {
		uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
		uint8_t opcode = *p & REBASE_OPCODE_MASK;
		++p;
		switch (opcode) {
			case REBASE_OPCODE_DONE:
				done = 1;
				break;
			case REBASE_OPCODE_SET_TYPE_IMM:
				type = immediate;
				break;
			case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				segmentIndex = immediate;
				if ( segmentIndex >= n )
					errx(1, "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (0..%d)",
							segmentIndex, n-1);
				address = segActualLoadAddress(segmentIndex) + read_uleb128(&p, end);
				segmentEndAddress = segActualEndAddress(segmentIndex);
				break;
			case REBASE_OPCODE_ADD_ADDR_ULEB:
				address += read_uleb128(&p, end);
				break;
			case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
				address += immediate*sizeof(uintptr_t);
				break;
			case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
				for (int i=0; i < immediate; ++i) {
					if ( address >= segmentEndAddress ) 
						errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
					rebaseAt(context, address, slide, type);
					address += sizeof(uintptr_t);
				}
				fgTotalRebaseFixups += immediate;
				break;
			case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
				count = read_uleb128(&p, end);
				for (uint32_t i=0; i < count; ++i) {
					if ( address >= segmentEndAddress ) 
						errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
					rebaseAt(context, address, slide, type);
					address += sizeof(uintptr_t);
				}
				fgTotalRebaseFixups += count;
				break;
			case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
				if ( address >= segmentEndAddress ) 
					errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
				rebaseAt(context, address, slide, type);
				address += read_uleb128(&p, end) + sizeof(uintptr_t);
				++fgTotalRebaseFixups;
				break;
			case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
				count = read_uleb128(&p, end);
				skip = read_uleb128(&p, end);
				for (uint32_t i=0; i < count; ++i) {
					if ( address >= segmentEndAddress ) 
						errx(1, "throwBadBindingAddress(0x%zx, 0x%zx, %d, %p, %p, %p);", address, segmentEndAddress, segmentIndex, start, end, p);
					rebaseAt(context, address, slide, type);
					address += skip + sizeof(uintptr_t);
				}
				fgTotalRebaseFixups += count;
				break;
			default:
				errx(1, "bad rebase opcode %d", *p);
		}
	}
}

#undef segActualEndAddress
#undef segActualLoadAddress

static void
exportAt(void *context, uintptr_t address, uint64_t other, const char *importName, const char *symbolName)
{
    assert(importName == NULL);
    INFO("#public(0x%zx) %s\n", *(uintptr_t *)context + address, symbolName);
    (void)(context && address && other && symbolName);
}

static void
processExportNode(const uint8_t *const start, const uint8_t *p, const uint8_t* const end, char *cummulativeString, int curStrOffset, void *context)
{
    if (p >= end) {
        errx(1, "malformed trie, node past end");
    }
    const uint8_t terminalSize = read_uleb128(&p, end);
    const uint8_t *children = p + terminalSize;
    if (terminalSize != 0) {
        /*uintptr_t nodeOffset = p - start;*/
        const char *name = strdup(cummulativeString);
        uint64_t address;
        uint64_t flags = read_uleb128(&p, end);
        uint64_t other;
        const char *importName;

        if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
            address = 0;
            other = read_uleb128(&p, end);
            importName = (char*)p;
        } else {
            address = read_uleb128(&p, end); 
            if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
                other = read_uleb128(&p, end);
            } else {
                other = 0;
            }
            importName = NULL;
        }
        exportAt(context, address, other, importName, name);
        free((char *)name);
    }

    const uint8_t childrenCount = *children++;
    const uint8_t *s = children;
    uint8_t i;
    for (i = 0; i < childrenCount; ++i) {
        int edgeStrLen = 0;
        while (*s != '\0') {
            cummulativeString[curStrOffset + edgeStrLen] = *s++;
            ++edgeStrLen;
        }
        cummulativeString[curStrOffset + edgeStrLen] = *s++;
        uint32_t childNodeOffset = read_uleb128(&s, end);
        if (childNodeOffset == 0) {
            errx(1, "malformed trie, childNodeOffset==0");
        }
        processExportNode(start, start + childNodeOffset, end, cummulativeString, curStrOffset + edgeStrLen, context);
    }
}

static void
do_export(const unsigned char *p, off_t sz, uint32_t export_off, uint32_t export_size, void *context)
{
    const unsigned char *q = p + export_off;
    const unsigned char *end = q + export_size;
    char *cummulativeString;
    if (q == end) {
        return;
    }
    cummulativeString = malloc(end - q);
    if (!cummulativeString) {
        errx(1, "out of memory");
    }
    processExportNode(q, q, end, cummulativeString, 0, context);
    free(cummulativeString);
    (void)sz;
}

static uint8_t *
load_kext(const char *filename, uintptr_t *dest, size_t *sz)
{
    int rv;
    struct macho *macho;
    uint8_t *buf;
    uint8_t p[0x1000];
    size_t size, offset;
    struct symtab_command *ksym = NULL;
    struct dysymtab_command *kdys = NULL;
    struct dyld_info_command *kdic = NULL;
    uintptr_t segments[2 * 16];
    unsigned num_segments = 0;
    size_t linkdelta = 0;
    uintptr_t writable = 0;
    int is64 = 0;
    unsigned i, j, k;
    const struct mach_header *hdr;
    const uint8_t *q;
    size_t hdrsz;

    *sz = 0;
    *dest = 0;

    /* since I'm not going to rewrite a full dyld-like code, I'm gonna make some assumptions:
     * segments (including LINKEDIT) come in order
     * sections are nicely laid down inside segments
     * after segments come the other commands: SYMTAB, DYSYMTAB
     * symbols, relocations are inside LINKEDIT
     */

    macho = mopen(filename, O_RDONLY, (struct mach_header *)kernel);
    if (!macho) {
        ERR("%s: not found\n", filename);
        return NULL;
    }

    size = mread(macho, p, sizeof(p), 0);
    if (size != sizeof(p)) {
        ERR("%s: bad mach-o\n", filename);
        mclose(macho);
        return NULL;
    }

    /* parse header, calculate total in-memory size */

    hdr = (struct mach_header *)p;
    q = p + sizeof(struct mach_header);

    if (IS64(p)) {
        is64 = 4;
    }
    q += is64;

    hdrsz = q - p + hdr->sizeofcmds;
    if (hdrsz > sizeof(p)) {
        ERR("%s: internal error\n", filename);
        mclose(macho);
        return NULL;
    }

    size = 0;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            seg->vmsize = round_page(seg->vmsize);
            size += seg->vmsize;
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            seg->vmsize = round_page(seg->vmsize);
            size += seg->vmsize;
        }
        if (cmd->cmd == LC_LOAD_DYLIB) {
            struct dylib_command *dyl = (struct dylib_command *)q;
            preload((char *)q + dyl->dylib.name.offset);
        }
        q = q + cmd->cmdsize;
    }

    rv = posix_memalign((void **)&buf, 0x1000, size);
    if (rv) {
        ERR("%s: out of memory\n", filename);
        mclose(macho);
        return NULL;
    }
    memset(buf, 0, size); /* XXX take care of S_ZEROFILL */
    *dest = (uintptr_t)buf;

    /* read segments in, calculate linkedit delta */

    q = p + sizeof(struct mach_header) + is64;

    offset = 0;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            struct section *sec = (struct section *)(seg + 1);
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                linkdelta = offset - seg->fileoff;
            }
            if (seg->filesize > seg->vmsize) {
                seg->filesize = seg->vmsize;
            }
            seg->vmaddr += *dest;
            for (j = 0; j < seg->nsects; j++) {
                sec[j].addr += *dest;
                assert(sec->reloff == 0 && sec->nreloc == 0);
                if (!strncmp(sec[j].sectname, "__mod_init_func", 16)) {
                    ctors = (uintptr_t *)(uintptr_t)sec[j].addr;
                    num_ctors = sec[j].size / sizeof(void *);
                }
                if (!strncmp(sec[j].sectname, "__mod_term_func", 16)) {
                    dtors = (uintptr_t *)(uintptr_t)sec[j].addr;
                    num_dtors = sec[j].size / sizeof(void *);
                }
                if (!strncmp(sec[j].sectname, "__eh_frame", 16)) {
                    eh_frame = (void *)(uintptr_t)sec[j].addr;
                }
            }
            size = mread(macho, buf + offset, seg->filesize, seg->fileoff);
            assert(size == seg->filesize);
            seg->fileoff = offset;
            if ((seg->initprot & 2) && !writable) {
                writable = offset;
            }
            assert(num_segments < 16);
            segments[num_segments * 2 + 0] = seg->vmaddr;
            segments[num_segments * 2 + 1] = seg->vmaddr + seg->vmsize;
            num_segments++;
            offset += seg->vmsize;
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            struct section_64 *sec = (struct section_64 *)(seg + 1);
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                linkdelta = offset - seg->fileoff;
            }
            if (seg->filesize > seg->vmsize) {
                seg->filesize = seg->vmsize;
            }
            seg->vmaddr += *dest;
            for (j = 0; j < seg->nsects; j++) {
                sec[j].addr += *dest;
                assert(sec->reloff == 0 && sec->nreloc == 0);
                if (!strncmp(sec[j].sectname, "__mod_init_func", 16)) {
                    ctors = (uintptr_t *)(uintptr_t)sec[j].addr;
                    num_ctors = sec[j].size / sizeof(void *);
                }
                if (!strncmp(sec[j].sectname, "__mod_term_func", 16)) {
                    dtors = (uintptr_t *)(uintptr_t)sec[j].addr;
                    num_dtors = sec[j].size / sizeof(void *);
                }
                if (!strncmp(sec[j].sectname, "__eh_frame", 16)) {
                    eh_frame = (void *)(uintptr_t)sec[j].addr;
                }
            }
            size = mread(macho, buf + offset, seg->filesize, seg->fileoff);
            assert(size == seg->filesize);
            seg->fileoff = offset;
            if ((seg->initprot & 2) && !writable) {
                writable = offset;
            }
            assert(num_segments < 16);
            segments[num_segments * 2 + 0] = seg->vmaddr;
            segments[num_segments * 2 + 1] = seg->vmaddr + seg->vmsize;
            num_segments++;
            offset += seg->vmsize;
        }
        q = q + cmd->cmdsize;
    }

    mclose(macho);

    /* fix header */

    memcpy(buf, p, hdrsz);

    /* solve imports, spot relocs */

    q = buf + sizeof(struct mach_header) + is64;

#define SLIDE(x) do { if (x) x += linkdelta; } while (0)
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SYMTAB) {
            struct symtab_command *sym = (struct symtab_command *)q;
            ksym = sym;
            SLIDE(sym->symoff);
            SLIDE(sym->stroff);
            if (is64) {
                struct nlist_64 *s = (struct nlist_64 *)(buf + sym->symoff);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if ((s[k].n_type & N_EXT) && GET_LIBRARY_ORDINAL(s[k].n_desc) > 0 && s[k].n_value == 0) {
                        s[k].n_value = solver((char *)buf + sym->stroff + s[k].n_un.n_strx);
                        continue;
                    }
                    s[k].n_value += *dest;
                }
            } else {
                struct nlist *s = (struct nlist *)(buf + sym->symoff);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if ((s[k].n_type & N_EXT) && GET_LIBRARY_ORDINAL(s[k].n_desc) > 0 && s[k].n_value == 0) {
                        s[k].n_value = solver((char *)buf + sym->stroff + s[k].n_un.n_strx);
                        continue;
                    }
                    s[k].n_value += *dest;
                }
            }
        }
        if (cmd->cmd == LC_DYSYMTAB) {
            struct dysymtab_command *dys = (struct dysymtab_command *)q;
            kdys = dys;
            SLIDE(dys->tocoff);
            SLIDE(dys->modtaboff);
            SLIDE(dys->extrefsymoff);
            SLIDE(dys->indirectsymoff);
            SLIDE(dys->extreloff);
            SLIDE(dys->locreloff);
        }
        if (cmd->cmd == LC_DYLD_INFO_ONLY) {
            struct dyld_info_command *dic = (struct dyld_info_command *)q;
            kdic = dic;
            SLIDE(dic->rebase_off);
            SLIDE(dic->bind_off);
            SLIDE(dic->weak_bind_off);
            SLIDE(dic->lazy_bind_off);
            SLIDE(dic->export_off);
        }
        q = q + cmd->cmdsize;
    }
#undef SLIDE

    /*if (kdic) {
        if (kdic->bind_off) {
            do_import(buf, kdic->bind_off, kdic->bind_size, segments, num_segments, dest, 0);
        }
        if (kdic->weak_bind_off) {
            assert(0);
        }
        if (kdic->lazy_bind_off) {
            do_import(buf, kdic->lazy_bind_off, kdic->lazy_bind_size, segments, num_segments, dest, BIND_TYPE_POINTER);
        }
        if (kdic->export_off) {
            do_export(buf, size, kdic->export_off, kdic->export_size, dest);
        }
    }*/

    /* apply relocs */

    if (kdic && kdic->rebase_off) {
        do_rebase(buf, kdic->rebase_off, kdic->rebase_size, segments, num_segments, dest);
    } else
    if (kdys && kdys->locreloff) {
        const struct relocation_info *r = (struct relocation_info *)(buf + kdys->locreloff);
        if (is64) {
            for (k = 0; k < kdys->nlocrel; k++, r++) {
                if (
#if 1 /* XXX horrible hack to reduce size */
                    (((uint32_t *)r)[1] >> 24) != 6
#else
                    r->r_pcrel || r->r_length != 3 || r->r_extern || r->r_type > GENERIC_RELOC_VANILLA
#endif
                   ) {
                    assert(0);
                }
                if (r->r_address & R_SCATTERED) {
                    assert(0);
                }
                *(uint64_t *)(buf + r->r_address + writable) += *dest;
            }
        } else {
            for (k = 0; k < kdys->nlocrel; k++, r++) {
                if (
#if 1 /* XXX horrible hack to reduce size */
                    (((uint32_t *)r)[1] >> 24) != 4
#else
                    r->r_pcrel || r->r_length != 2 || r->r_extern || r->r_type > GENERIC_RELOC_VANILLA
#endif
                   ) {
                    assert(0);
                }
                if (r->r_address & R_SCATTERED) {
                    assert(0);
                }
                *(uint32_t *)(buf + r->r_address + writable) += *dest;
            }
        }
    }

    /* apply externs */

    if (kdys && kdys->extreloff && ksym->symoff) {
        const struct relocation_info *r = (struct relocation_info *)(buf + kdys->extreloff);
        if (is64) {
            const struct nlist_64 *s = (struct nlist_64 *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nextrel; k++, r++) {
                assert(!r->r_pcrel && r->r_length == 3 && r->r_extern && r->r_type == GENERIC_RELOC_VANILLA);
                INFO("extern %d: 0x%zx = %s\n", r->r_symbolnum, r->r_address + writable, (char *)buf + ksym->stroff + s[r->r_symbolnum].n_un.n_strx);
                *(uint64_t *)(buf + r->r_address + writable) = s[r->r_symbolnum].n_value;
            }
        } else {
            const struct nlist *s = (struct nlist *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nextrel; k++, r++) {
                assert(!r->r_pcrel && r->r_length == 2 && r->r_extern && r->r_type == GENERIC_RELOC_VANILLA);
                INFO("extern %d: 0x%zx = %s\n", r->r_symbolnum, r->r_address + writable, (char *)buf + ksym->stroff + s[r->r_symbolnum].n_un.n_strx);
                *(uint32_t *)(buf + r->r_address + writable) = s[r->r_symbolnum].n_value;
            }
        }
    }

    /* indirect symbols */

    q = buf + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (struct segment_command *)q;
            struct section *sec = (struct section *)(seg + 1);
            for (j = 0; j < seg->nsects; j++) {
                if ((sec[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                    (sec[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    const struct nlist *s = (struct nlist *)(buf + ksym->symoff);
                    unsigned stride = sizeof(void *);
                    unsigned count = sec[j].size / stride;
                    unsigned k, n = sec[j].reserved1;
                    for (k = 0; k < count && n + k < kdys->nindirectsyms; k++) {
                        unsigned int z = ((unsigned *)(buf + kdys->indirectsymoff))[k + n];
                        if (z & INDIRECT_SYMBOL_ABS) {
                            continue;
                        }
                        if (z & INDIRECT_SYMBOL_LOCAL) {
                            *(uint32_t *)((uintptr_t)sec[j].addr + k * stride) += *dest;
                            continue;
                        }
                        INFO("indirect %d: 0x%x = %s\n", z, s[z].n_value, (char *)buf + ksym->stroff + s[z].n_un.n_strx);
                        *(uint32_t *)((uintptr_t)sec[j].addr + k * stride) = s[z].n_value;
                    }
                }
            }
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)q;
            struct section_64 *sec = (struct section_64 *)(seg + 1);
            for (j = 0; j < seg->nsects; j++) {
                if ((sec[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                    (sec[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    const struct nlist_64 *s = (struct nlist_64 *)(buf + ksym->symoff);
                    unsigned stride = sizeof(void *);
                    unsigned count = sec[j].size / stride;
                    unsigned k, n = sec[j].reserved1;
                    for (k = 0; k < count && n + k < kdys->nindirectsyms; k++) {
                        unsigned int z = ((unsigned *)(buf + kdys->indirectsymoff))[k + n];
                        if (z & INDIRECT_SYMBOL_ABS) {
                            continue;
                        }
                        if (z & INDIRECT_SYMBOL_LOCAL) {
                            *(uint64_t *)((uintptr_t)sec[j].addr + k * stride) += *dest;
                            continue;
                        }
                        INFO("indirect %d: 0x%lx = %s\n", z, s[z].n_value, (char *)buf + ksym->stroff + s[z].n_un.n_strx);
                        *(uint64_t *)(sec[j].addr + k * stride) = s[z].n_value;
                    }
                }
            }
        }
        q = q + cmd->cmdsize;
    }

    /* imported (should be solved already) */

    if (kdys && kdys->nundefsym && ksym->symoff) {
        if (is64) {
            const struct nlist_64 *s = (struct nlist_64 *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nundefsym; k++) {
                if (s[k + kdys->iundefsym].n_value == 0) {
                    ERR("%s: unresolved symbol %s\n", filename, (char *)buf + ksym->stroff + s[k + kdys->iundefsym].n_un.n_strx);
                    free(buf);
                    return NULL;
                }
            }
        } else {
            const struct nlist *s = (struct nlist *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nundefsym; k++) {
                if (s[k + kdys->iundefsym].n_value == 0) {
                    ERR("%s: unresolved symbol %s\n", filename, (char *)buf + ksym->stroff + s[k + kdys->iundefsym].n_un.n_strx);
                    free(buf);
                    return NULL;
                }
            }
        }
    }

    /* exported */

    if (kdys && kdys->nextdefsym && ksym->symoff) {
        if (is64) {
            const struct nlist_64 *s = (struct nlist_64 *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nextdefsym; k++) {
                INFO("public(0x%lx) %s\n", s[k + kdys->iextdefsym].n_value, (char *)buf + ksym->stroff + s[k + kdys->iextdefsym].n_un.n_strx);
                if (!strcmp(UNDERSCORE(XSYMBOL), (char *)buf + ksym->stroff + s[k + kdys->iextdefsym].n_un.n_strx)) {
                    the_ptr = s[k + kdys->iextdefsym].n_value;
                }
            }
        } else {
            const struct nlist *s = (struct nlist *)(buf + ksym->symoff);
            for (k = 0; k < kdys->nextdefsym; k++) {
                INFO("public(0x%x) %s\n", s[k + kdys->iextdefsym].n_value, (char *)buf + ksym->stroff + s[k + kdys->iextdefsym].n_un.n_strx);
                if (!strcmp(UNDERSCORE(XSYMBOL), (char *)buf + ksym->stroff + s[k + kdys->iextdefsym].n_un.n_strx)) {
                    the_ptr = s[k + kdys->iextdefsym].n_value;
                }
            }
        }
    }

    if (kdys) {
        kdys->nlocrel = 0; /* XXX nuke relocs */
        kdys->nextrel = 0; /* XXX nuke exts */
    }

    rv = mprotect(buf, writable, PROT_READ | PROT_EXEC);
    if (rv) {
        ERR("%s: map error\n", filename);
        free(buf);
        return NULL;
    }

    *sz = offset;
    return buf;
}

static const char *
build_path(void)
{
    static char buf[4096];
    Dl_info info;
    int rv = dladdr((void *)(uintptr_t)build_path, &info);
    if (rv && info.dli_fname) {
        size_t len;
        const char *p = strrchr(info.dli_fname, '.');
        if (p && p > info.dli_fname) {
            len = p - info.dli_fname;
        } else {
            len = strlen(info.dli_fname);
        }
        if (len + 1 + sizeof("dylib") > sizeof(buf)) {
            return NULL;
        }
        memcpy(buf, info.dli_fname, len);
        buf[len++] = '.';
        strcpy(buf + len, "dylib");
        return buf;
    }
    return NULL;
}

void
initme(void)
{
    const char *path;
    uint8_t *buf;
    uintptr_t dest = 0;
    size_t sz = 0;
    path = build_path();
    if (!path) {
        return;
    }
    INFO("load: %s\n", path);
    buf = load_kext(path, &dest, &sz);
    if (!buf) {
        num_dtors = 0;
        return;
    }
    INFO("base: %p\n", (void *)buf);
    while (num_ctors-- > 0) {
        uintptr_t func = (uintptr_t)*ctors++;
        INFO("ctor: 0x%zx\n", func);
        ((void (*)())func)();
    }
    if (the_ptr) {
        memcpy(XSYMBOL, (void *)the_ptr, sizeof(XSYMBOL));
    } else {
        ERR("symbol %s not found\n", UNDERSCORE(XSYMBOL));
    }
}

void
finime(void)
{
    // XXX actual destruction is done by __cxa_atexit
    while (num_dtors-- > 0) {
        uintptr_t func = (uintptr_t)*dtors++;
        INFO("dtor: 0x%zx\n", func);
        ((void (*)())func)();
    }
}

#ifdef HAVE_MAIN
int
main(void)
{
    initme();
    printf("%x\n", *XSYMBOL);
    finime();
    return 0;
}
#endif
