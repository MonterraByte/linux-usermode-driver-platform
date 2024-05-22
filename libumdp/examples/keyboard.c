// 8042 PS/2 keyboard driver

#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <umdp.h>

#define DATA_PORT 0x60u
#define COMMAND_PORT 0x64u
#define PORT1_IRQ 1

#define TRY(f, err)                                      \
    {                                                    \
        int ret = f;                                     \
        if (ret != 0) {                                  \
            fprintf(stderr, "[%s] " err "\n", __func__); \
            return ret;                                  \
        }                                                \
    }
#define TRY_UMDP(f, err)                                                         \
    {                                                                            \
        int ret = f;                                                             \
        if (ret != 0) {                                                          \
            fprintf(stderr, "[%s] " err ": %s\n", __func__, umdp_strerror(ret)); \
            return 1;                                                            \
        }                                                                        \
    }
#define TRY_UMDP_FMT(f, err, ...)                                                             \
    {                                                                                         \
        int ret = f;                                                                          \
        if (ret != 0) {                                                                       \
            fprintf(stderr, "[%s] " err ": %s\n", __func__, __VA_ARGS__, umdp_strerror(ret)); \
            return 1;                                                                         \
        }                                                                                     \
    }

#define TRY_READ_STATUS(out) \
    TRY_UMDP(umdp_devio_read_u8(connection, COMMAND_PORT, out), "failed to read the status register")
#define TRY_READ_DATA(out) TRY_UMDP(umdp_devio_read_u8(connection, DATA_PORT, out), "failed to read from the data port")

#define TRY_WRITE_CONTROL(value) \
    TRY_UMDP_FMT(                \
        umdp_devio_write_u8(connection, COMMAND_PORT, value), "failed to write 0x%x to the control register", value)
#define TRY_WRITE_DATA(value) \
    TRY_UMDP_FMT(umdp_devio_write_u8(connection, DATA_PORT, value), "failed to write 0x%x to the data port", value)

#define BIT(n) (1u << n)

const struct timespec sleep_time = {
    .tv_sec = 0,
    .tv_nsec = 1000,
};

inline static bool output_buffer_is_full(uint8_t status) {
    return status & BIT(0u);
}

static int wait_until_output_buffer_is_full(umdp_connection* connection) {
    uint8_t status;
    while (true) {
        TRY_READ_STATUS(&status);
        if (output_buffer_is_full(status)) {
            return 0;
        }
        nanosleep(&sleep_time, NULL);
    }
}

inline static bool input_buffer_is_full(uint8_t status) {
    return status & BIT(1u);
}

static int wait_until_input_buffer_is_clear(umdp_connection* connection) {
    uint8_t status;
    while (true) {
        TRY_READ_STATUS(&status);
        if (!input_buffer_is_full(status)) {
            return 0;
        }
        nanosleep(&sleep_time, NULL);
    }
}

static int send_controller_command_and_receive_response(
    umdp_connection* connection, uint8_t command, uint8_t* response) {
    TRY_WRITE_CONTROL(command);
    TRY(wait_until_output_buffer_is_full(connection), "failed to wait for output buffer");
    TRY_READ_DATA(response);
    return 0;
}

static int read_controller_configuration(umdp_connection* connection, uint8_t* output) {
    return send_controller_command_and_receive_response(connection, 0x20u, output);
}

static int write_controller_configuration(umdp_connection* connection, uint8_t config) {
    TRY_WRITE_CONTROL(0x60u);
    TRY(wait_until_input_buffer_is_clear(connection), "failed to wait for input buffer");
    TRY_WRITE_DATA(config);
    return 0;
}

static int init_ps2_controller(umdp_connection* connection) {
    // disable devices
    TRY_WRITE_CONTROL(0xADu);
    TRY_WRITE_CONTROL(0xA7u);

    // flush output buffer
    while (true) {
        uint8_t status;
        TRY_READ_STATUS(&status);
        if (!output_buffer_is_full(status)) {
            break;
        }

        uint8_t unused;
        TRY_READ_DATA(&unused);
    }

    // disable interrupts and translation
    uint8_t config;
    TRY(read_controller_configuration(connection, &config), "failed to read controller configuration");
    bool single_channel_controller = config & BIT(5u);
    config &= 0xFFu ^ (BIT(0u) | BIT(1u) | BIT(6u));  // turn off bits 0, 1 and 6
    TRY(write_controller_configuration(connection, config), "failed to write controller configuration");

    // self-test
    uint8_t test_result;
    TRY(send_controller_command_and_receive_response(connection, 0xAAu, &test_result),
        "failed to send controller self-test command");
    if (test_result != 0x55u) {
        fprintf(stderr, "PS/2 controller self-test failed (returned 0x%x instead of 0x55)\n", test_result);
        return 1;
    }

    // set the configuration again, as some controllers may reset during self-test
    TRY(write_controller_configuration(connection, config), "failed to write controller configuration");

    if (!single_channel_controller) {
        // disable the second PS/2 port
        TRY_WRITE_CONTROL(0xA7u);
    }

    // test the PS/2 port
    TRY(send_controller_command_and_receive_response(connection, 0xABu, &test_result),
        "failed to send port self-test command");
    if (test_result != 0u) {
        fprintf(stderr, "PS/2 port self-test failed (returned 0x%x instead of 0x00)\n", test_result);
        return 1;
    }

    // enable first device
    TRY_WRITE_CONTROL(0xAEu);
    return 0;
}

static int enable_ps2_interrupts(umdp_connection* connection) {
    uint8_t config;
    TRY(read_controller_configuration(connection, &config), "failed to read controller configuration");

    TRY_UMDP(umdp_interrupt_subscribe(connection, PORT1_IRQ), "failed to subscribe to IRQ 1");

    config |= BIT(0);
    int ret = write_controller_configuration(connection, config);
    if (ret != 0) {
        ret = umdp_interrupt_unsubscribe(connection, PORT1_IRQ);
        fprintf(stderr, "[%s] failed to write controller configuration\n", __func__);
        if (ret != 0) {
            fprintf(stderr, "[%s] failed to unsubscribe from IRQ 1: %s\n", __func__, umdp_strerror(ret));
        }
        return ret;
    }

    return 0;
}

static int request_ps2_io_ports(umdp_connection* connection) {
    TRY_UMDP(umdp_devio_request(connection, DATA_PORT, 1u), "failed to request data port (0x60)");

    int ret = umdp_devio_request(connection, COMMAND_PORT, 1u);
    if (ret != 0) {
        fprintf(stderr, "[%s] failed to request command port (0x64): %s\n", __func__, umdp_strerror(ret));
        TRY_UMDP(umdp_devio_release(connection, DATA_PORT, 1), "failed to release data port (0x60)");
        return 1;
    }
    return 0;
}

static bool should_exit = false;

static int handle_ps2_interrupts(umdp_connection* connection) {
    while (!should_exit) {
        uint32_t irq;
        TRY_UMDP(umdp_receive_interrupt(connection, &irq), "failed to receive interrupt");
        if (irq != PORT1_IRQ) {
            continue;
        }

        uint8_t data;
        TRY_READ_DATA(&data);
        printf("Received 0x%x\n", data);
    }
    return 0;
}

static void sigint_handler(__attribute__((unused)) int signum) {
    should_exit = true;
}

static int install_sigint_handler(void) {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    return 0;
}

int main(void) {
    int ret = 0;
    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }

    ret = request_ps2_io_ports(connection);
    if (ret != 0) {
        goto exit;
    }

    ret = init_ps2_controller(connection);
    if (ret != 0) {
        goto exit_with_ports;
    }

    ret = enable_ps2_interrupts(connection);
    if (ret != 0) {
        goto exit_with_ports;
    }

    if (install_sigint_handler() == 0) {
        handle_ps2_interrupts(connection);
    }

    puts("Exiting");

    ret = umdp_interrupt_unsubscribe(connection, PORT1_IRQ);
    if (ret != 0) {
        fprintf(stderr, "failed to unsubscribe from IRQ 1: %s\n", umdp_strerror(ret));
    }
exit_with_ports:
    ret = umdp_devio_release(connection, DATA_PORT, 1);
    if (ret != 0) {
        fprintf(stderr, "failed to release data port (0x60): %s\n", umdp_strerror(ret));
    }
    ret = umdp_devio_release(connection, COMMAND_PORT, 1);
    if (ret != 0) {
        fprintf(stderr, "failed to release command port (0x64): %s\n", umdp_strerror(ret));
    }
exit:
    umdp_disconnect(connection);
    return ret;
}
