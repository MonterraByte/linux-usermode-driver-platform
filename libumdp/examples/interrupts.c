#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <umdp.h>

void parse_args(int argc, char* argv[], uint32_t* irq) {
    if (argc != 2) {
        fprintf(stderr, "USAGE: %s IRQ\n", argv[0]);
        exit(1);
    }

    errno = 0;
    unsigned long irq_ul = strtoul(argv[1], NULL, 0);
    if (errno != 0) {
        perror("Invalid IRQ");
        exit(1);
    }
    if (irq_ul > UINT32_MAX) {
        fprintf(stderr, "value out of range\n");
        exit(1);
    }

    *irq = (uint32_t) irq_ul;
}

int main(int argc, char* argv[]) {
    uint32_t irq;
    parse_args(argc, argv, &irq);

    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }


    int ret = umdp_interrupt_subscribe(connection, irq);
    if (ret != 0) {
        fprintf(stderr, "umdp_interrupt_subscribe returned %d\n", ret);
        umdp_disconnect(connection);
        return 1;
    }

    printf("Subscribed to IRQ %u successfully\n", irq);
    uint32_t received_irq;
    for (size_t i = 0; i < 10; i++) {
        ret = umdp_receive_interrupt(connection, &received_irq);
        if (ret != 0) {
            fprintf(stderr, "umdp_receive_interrupt returned %d\n", ret);
            ret = umdp_interrupt_unsubscribe(connection, irq);
            if (ret != 0) {
                fprintf(stderr, "umdp_interrupt_unsubscribe returned %d\n", ret);
            }
            umdp_disconnect(connection);
            return 1;
        }
        printf("Interrupt from IRQ %d\n", received_irq);
    }
    printf("Received 10 interrupt notifications, exiting\n");

    ret = umdp_interrupt_unsubscribe(connection, irq);
    if (ret != 0) {
        fprintf(stderr, "umdp_interrupt_unsubscribe returned %d\n", ret);
    }
    umdp_disconnect(connection);
    return 0;
}
