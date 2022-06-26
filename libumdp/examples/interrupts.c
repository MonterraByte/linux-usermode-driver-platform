#include <stdio.h>

#include <umdp.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }


    int ret = umdp_interrupt_subscribe(connection, 0);
    if (ret != 0) {
        fprintf(stderr, "umdp_interrupt_subscribe returned %d\n", ret);
        return 1;
    }

    printf("Subscribed to IRQ 0 successfully\n");
    sleep(1);
    uint32_t irq;
    //for (int i = 0; i < 10; i++) {
        ret = umdp_receive_interrupt(connection, &irq);
        if (ret != 0) {
            fprintf(stderr, "umdp_receive_interrupt returned %d\n", ret);
            return 1;
        }
        printf("IRQ: %d\n", irq);
    //    sleep(1);
    //}

    printf("Disconnecting\n");
    umdp_interrupt_unsubscribe(connection, 0);
    umdp_disconnect(connection);
    return 0;
}
