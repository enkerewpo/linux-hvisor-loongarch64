#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

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

    // char c;
    // while (1)
    // {
    //     c = fgetc(f2);
    //     fprintf(f, "you input: %c\n", c);
    //     fflush(f);
    // }

    // shell loop
    while (1)
    {
        fprintf(f, "wsh> ");
        fflush(f);
        char cmd[100];
        fscanf(f2, "%s", cmd);
        fprintf(f, "You entered: %s\n", cmd);
        if (strcmp(cmd, "exit") == 0)
        {
            break;
        }
        if (strcmp(cmd, "hello") == 0)
        {
            fprintf(f, "Hello world!\n");
            continue;
        }
        // run process but all input and output are from/to hvc0
        fprintf(f, "Running %s command...\n", cmd);
        int pid = fork();
        if (pid == 0)
        {
            dup2(fileno(f), STDIN_FILENO);
            dup2(fileno(f), STDOUT_FILENO);
            dup2(fileno(f), STDERR_FILENO);
            execlp(cmd, cmd, NULL);
        }
        waitpid(pid, NULL, 0);
        fprintf(f, "Command %s finished.\n", cmd);
    }

    fprintf(f, "Goodbye!\n");

    fclose(f2);
    fclose(f);

    // can't reach here
    while (1)
        ;
    return 0;
}