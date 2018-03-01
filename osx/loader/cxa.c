#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <unwind.h>

#define INFO(args...) printf(args)
#define ERR(args...) fprintf(stderr, args)

#define EC_STR "%c%c%c%c%c%c%c%d"
#define EC_VAL(x) (int)((x >> 56) & 0xFF), (int)((x >> 48) & 0xFF), (int)((x >> 40) & 0xFF), (int)((x >> 32) & 0xFF), (int)((x >> 24) & 0xFF), (int)((x >> 16) & 0xFF), (int)((x >> 8) & 0xFF), (int)(x & 0xFF)

typedef void (*cxa_throw_fn)(void *thrown_exception, void *tinfo, void (*dest)(void *));
void __register_frame(const void *begin);
void __register_frame_info(const void *begin, void *object);
void *eh_frame __attribute__((visibility("hidden")));

/*
_Unwind_Reason_Code __attribute__((visibility("hidden")))
gxx_personality_v0(int version, _Unwind_Action actions, _Unwind_Exception_Class exceptionClass, struct _Unwind_Exception *unwind_exception, struct _Unwind_Context *context)
{
    static _Unwind_Personality_Fn func;
    if (!func) {
        func = (_Unwind_Personality_Fn)(uintptr_t)dlsym(RTLD_DEFAULT, "__gxx_personality_v0");
    }
    _Unwind_Reason_Code rv;
    INFO("%s(%d, %d, "EC_STR", %p, %p)\n", __func__, version, actions, EC_VAL(exceptionClass), (void *)unwind_exception, (void *)context);
    rv = func(version, actions, exceptionClass, unwind_exception, context);
    INFO("-> %d\n", rv);
    return rv;
}
*/

void __attribute__((visibility("hidden")))
cxa_throw(void *thrown_exception, void *tinfo, void (*dest)(void *))
{
    static cxa_throw_fn func;
    if (!func) {
        func = (cxa_throw_fn)(uintptr_t)dlsym(RTLD_DEFAULT, "__cxa_throw");
        if (eh_frame) {
#ifdef __APPLE__
            // XXX this is probably wrong as hell, but know this:
            // XXX on Darwin __register_frame() takes a single FDE
            uint32_t Size, Offset;
            const char *P = eh_frame;
            do {
                Size = *(uint32_t *)P;
                if (!Size) {
                    break;
                }
                P += 4 + Size;
                do {
                    Size = *(uint32_t *)P;
                    if (!Size) {
                        break;
                    }
                    Offset = *(uint32_t *)(P + 4);
                    if (!Offset) {
                        break;
                    }
                    INFO("__register_fde(%p)\n", (void *)P);
                    __register_frame(P);
                    P += 4 + Size;
                } while (Size);
            } while (Size);
#else
            static char object[256]; // XXX or just let __register_frame() allocate one
            INFO("__register_frame(%p)\n", eh_frame);
            __register_frame_info(eh_frame, &object);
#endif
        } else {
            ERR("eh_frame is missing. prepare to die\n");
        }
    }
    INFO("%s(%p, %p, 0x%zx)\n", __func__, thrown_exception, tinfo, (uintptr_t)dest);
    func(thrown_exception, tinfo, dest);
}
