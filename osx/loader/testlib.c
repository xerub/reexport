#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int exposed = 5;

static void __attribute__((constructor))
initfunc(void)
{
    printf("initialize\n");
}

static void __attribute__((destructor))
termfunc(void)
{
    printf("terminate\n");
}

int
square(int x)
{
    return x * x;
}

int
hello(char *who)
{
    return printf("hello %s\n", who);
}

int
plus(int x)
{
    try {
        throw(1);
        return x + x;
    } catch(...) {
        printf("caught\n");
        return -x;
    }
}

#ifdef __cplusplus
}
#endif
