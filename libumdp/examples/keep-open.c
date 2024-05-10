#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <umdp.h>

int main(void) {
    printf("PID: %d\n", getpid());

    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }

    char* reply = umdp_echo(connection, "message");
    if (reply == NULL) {
        fprintf(stderr, "umdp_echo returned NULL\n");
        umdp_disconnect(connection);
        return 1;
    }
    free(reply);

    printf("Connection established. Press Enter to close the connection.");

    char* lineptr = NULL;
    size_t len;
    getline(&lineptr, &len, stdin);
    free(lineptr);

    puts("Disconnecting");
    umdp_disconnect(connection);
    return 0;
}
