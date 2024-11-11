#include <stdio.h>
#include <unistd.h>

int main() {
    int wait_time = 2;
    for (int i = 0; i < wait_time; i++) {
        printf("Waiting for %d more seconds...\n", wait_time - i);
        sleep(1);
    }
    int pid = getpid();
    printf("init process pid: %d\n", pid);
    system("uname -a");
    printf("Hello, world from my userspace init! this is for testing input/output to virtio console\n");
    char buf[1024];
    while(1) {
        printf("> ");
        fgets(buf, 1024, stdin);
        printf("You entered: %s", buf);
        if (buf[0] == 'q') {
            break;
        }
    }
    printf("Goodbye! (but we're not actually going anywhere)\n");
    while(1) {}
    return 0;
}