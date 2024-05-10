#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <umdp.h>

#define BIT(n) (1 << (n))

#define TIMER_FREQ 1193182
#define TIMER_0_IRQ 0

#define TIMER_0_PORT 0x40
#define TIMER_CTRL_PORT 0x43

#define TIMER_RB_CMD (BIT(1) | BIT(5) | BIT(6) | BIT(7))
#define TIMER_0_CONFIG (BIT(1) | BIT(2) | BIT(4) | BIT(5))

umdp_connection* setup(void) {
    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        exit(1);
    }

    int ret = umdp_devio_request(connection, TIMER_0_PORT, TIMER_CTRL_PORT - TIMER_0_PORT + 1);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_request returned %d\n", ret);
        umdp_disconnect(connection);
        exit(1);
    }

    return connection;
}

void cleanup(umdp_connection* connection) {
    int ret = umdp_devio_release(connection, TIMER_0_PORT, TIMER_CTRL_PORT - TIMER_0_PORT + 1);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_release returned %d\n", ret);
    }

    umdp_disconnect(connection);
}

int get_conf(umdp_connection* connection, uint8_t* out) {
    printf("Sending byte %x to port %x\n", TIMER_RB_CMD, TIMER_CTRL_PORT);
    int ret = umdp_devio_write_u8(connection, TIMER_CTRL_PORT, TIMER_RB_CMD);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_write_u8 returned %d\n", ret);
        return ret;
    }

    printf("Reading from port %x\n", TIMER_0_PORT);
    ret = umdp_devio_read_u8(connection, TIMER_0_PORT, out);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_read_u8 returned %d\n", ret);
        return ret;
    }

    return 0;
}

int set_conf(umdp_connection* connection, uint16_t counter) {
    printf("Sending byte %x to port %x\n", TIMER_0_CONFIG, TIMER_CTRL_PORT);
    int ret = umdp_devio_write_u8(connection, TIMER_CTRL_PORT, TIMER_0_CONFIG);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_write_u8 returned %d\n", ret);
        return ret;
    }

    printf("Sending byte %x to port %x\n", counter & 0xFF, TIMER_0_PORT);
    ret = umdp_devio_write_u8(connection, TIMER_0_PORT, counter & 0xFF);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_write_u8 returned %d\n", ret);
        return ret;
    }

    printf("Sending byte %x to port %x\n", (counter & 0xFF00) >> 8, TIMER_0_PORT);
    ret = umdp_devio_write_u8(connection, TIMER_0_PORT, (counter & 0xFF00) >> 8);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_write_u8 returned %d\n", ret);
        return ret;
    }

    return 0;
}

void print_status(uint8_t status) {
    printf("Base: %s\n", status & BIT(0) ? "BCD" : "binary");
    printf("Operating mode: %d\n", (status & (BIT(1) | BIT(2) | BIT(3))) >> 1);
    printf("Initialization mode:");
    if (status & BIT(4)) {
        printf(" LSB");
    }
    if (status & BIT(5)) {
        printf(" MSB");
    }
    printf("\n");
}

int main(void) {
    umdp_connection* connection = setup();

    uint8_t status = 0;
    int ret = get_conf(connection, &status);
    if (ret != 0) {
        fprintf(stderr, "get_conf returned %d\n", ret);
        cleanup(connection);
        return 1;
    }

    printf("Timer 0 status: %#x\n", status);
    print_status(status);

    printf("Configuring timer 0...\n");
    ret = set_conf(connection, TIMER_FREQ / 60);
    if (ret != 0) {
        fprintf(stderr, "set_conf returned %d\n", ret);
        cleanup(connection);
        return 1;
    }

    uint8_t new_status = 0;
    ret = get_conf(connection, &new_status);
    if (ret != 0) {
        fprintf(stderr, "get_conf returned %d\n", ret);
        cleanup(connection);
        return 1;
    }

    printf("Timer 0 status: %#x\n", new_status);
    print_status(new_status);

    printf("Enabling interrupts for timer 0...\n");
    ret = umdp_interrupt_subscribe(connection, TIMER_0_IRQ);
    if (ret != 0) {
        fprintf(stderr, "umdp_interrupt_subscribe returned %d\n", ret);
        cleanup(connection);
        return 1;
    }

    for (int i = 0; i < 10; i++) {
        uint32_t irq;
        ret = umdp_receive_interrupt(connection, &irq);
        if (ret != 0) {
            fprintf(stderr, "umdp_receive_interrupt returned %d\n", ret);
        }
        printf("Received an interrupt (IRQ %u)\n", irq);
    }
    printf("Received 10 interrupt notifications, exiting\n");

    ret = umdp_interrupt_unsubscribe(connection, TIMER_0_IRQ);
    if (ret != 0) {
        fprintf(stderr, "umdp_interrupt_unsubscribe returned %d\n", ret);
        cleanup(connection);
        return 1;
    }

    cleanup(connection);
    return 0;
}
