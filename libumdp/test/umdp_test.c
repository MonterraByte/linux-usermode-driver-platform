#include <stdio.h>
#include <unistd.h>

#include <umdp.h>

int main(int argc, char **argv) {
    if(argc != 1) {
        printf("%s takes no arguments.\n", argv[0]);
        return 1;
    }

    sleep(20);

    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        printf("umdp_init returned NULL\n");
        return 1;
    }

    umdp_echo(connection, "Hello World!");
    umdp_echo(connection, "Hello World number 2!");
    /*char* reply = umdp_echo(connection, "Hello World!");
    if (reply == NULL) {
        printf("umdp_echo returned NULL\n");
        umdp_destroy(connection);
        return 1;
    }
    printf("%s\n", reply);*/

    umdp_destroy(connection);
    return 0;
}
