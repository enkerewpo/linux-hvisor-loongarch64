#include <stdio.h>
#include <unistd.h>

int main()
{
    const char *hvc = "/dev/hvc0";
    FILE *f = fopen(hvc, "w");
    FILE *f2 = fopen(hvc, "r");
    if (f == NULL || f2 == NULL)
    {
        return 1;
    }

    fprintf(f, "Hello world from virtio wsh!\n");

    char c;
    while (1)
    {
        c = fgetc(f2);
        fprintf(f, "you input: %c\n", c);
        fflush(f);
    }

    fclose(f);
    // can't reach here
    while (1)
        ;
    return 0;
}