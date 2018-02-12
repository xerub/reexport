int x = 5;

int
alpha(void)
{
    x++;
    return 9;
}

#include <stdio.h>

static void __attribute__((constructor))
initme(void)
{
    printf("here A: x: *%p = %u\n", (void *)&x, x);
}
