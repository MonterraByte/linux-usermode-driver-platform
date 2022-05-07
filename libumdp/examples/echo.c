#include <stdio.h>
#include <stdlib.h>

#include <umdp.h>

int main(int argc, char* argv[]) {
    char* message = "";
    if (argc > 2) {
        fprintf(stderr, "USAGE: %s message\n", argv[0]);
        return 1;
    }
    if (argc == 2) {
        message = argv[1];
    }

    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }

    char* reply = umdp_echo(connection, message);
    if (reply == NULL) {
        fprintf(stderr, "umdp_echo returned NULL\n");
        umdp_disconnect(connection);
        return 1;
    }

    printf("%s\n", reply);
    free(reply);

    umdp_disconnect(connection);
    return 0;
}
