#include <stdio.h>
#include <unistd.h>

int main()
{
    // print something into /dev/hvc0 for testing virtio console
    const char *target_device = "/dev/hvc0";
    FILE *f = fopen(target_device, "w");
    if (f == NULL)
    {
        printf("Failed to open %s\n", target_device);
        return 1;
    }
    printf("Writing to %s\n", target_device);
    int count = 10;
    while (count--)
    {
        fprintf(f, "Hello, world!\n");
    }
    fflush(f);
    fclose(f);

    // can't reach here
    while (1)
        ;
    return 0;
}