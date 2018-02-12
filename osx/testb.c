#include <stdio.h>

extern int x;
extern int alpha(void);

extern int y;
extern int beta(void);

int
main(void)
{
    printf("here C: x: *%p = %u\n", (void *)&x, x);
    printf("here C: y: *%p = %u\n", (void *)&y, y);
    int a = alpha();
    int b = beta();
    printf("x=%d, y=%d\n", x, y);
    printf("a=%d, b=%d\n", a, b);
    y = 1;
    a = alpha();
    b = beta();
    printf("x=%d, y=%d\n", x, y);
    return 0;
}
