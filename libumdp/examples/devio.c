#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umdp.h>

typedef enum {
    READ,
    WRITE,
} operation;

char* argv0;
void print_usage() {
    fprintf(stderr, "USAGE: %s read port\n       %s write port value\n", argv0, argv0);
    exit(1);
}

void parse_args(int argc, char* argv[], operation* op, uint64_t* port, uint8_t* value) {
    if (argc < 2) {
        print_usage();
    }

    if (strcmp(argv[1], "read") == 0) {
        *op = READ;
        if (argc != 3) {
            print_usage();
        }
    } else if (strcmp(argv[1], "write") == 0) {
        *op = WRITE;
        if (argc != 4) {
            print_usage();
        }

        errno = 0;
        unsigned long value_ul = strtoul(argv[3], NULL, 0);
        if (errno != 0) {
            perror("invalid value");
            exit(1);
        } else if (value_ul > UINT8_MAX) {
            fprintf(stderr, "value cannot be larger than %d\n", UINT8_MAX);
            exit(1);
        }
        *value = (uint8_t) value_ul;
    } else {
        print_usage();
    }

    errno = 0;
    *port = strtoul(argv[3], NULL, 0);
    if (errno != 0) {
        perror("invalid port value");
        exit(1);
    }
}

void devio_read(umdp_connection* connection, uint64_t port) {
    uint8_t value;
    int ret = umdp_devio_read_u8(connection, port, &value);
    if (ret == 0) {
        printf("%u (%x)\n", value, value);
    } else {
        fprintf(stderr, "read failed with code %d\n", ret);
    }
}

void devio_write(umdp_connection* connection, uint64_t port, uint8_t value) {
    int ret = umdp_devio_write_u8(connection, port, value);
    if (ret != 0) {
        fprintf(stderr, "write failed with code %d\n", ret);
    }
}

int main(int argc, char* argv[]) {
    argv0 = argv[0];

    operation op;
    uint64_t port;
    uint8_t value;
    parse_args(argc, argv, &op, &port, &value);

    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }

    int ret = umdp_devio_request(connection, port, 1);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_request returned %d\n", ret);
        umdp_disconnect(connection);
        return 1;
    }

    switch (op) {
        case READ:
            devio_read(connection, port);
            break;
        case WRITE: {
            devio_write(connection, port, value);
            break;
        }
    }

    ret = umdp_devio_release(connection, port, 1);
    if (ret != 0) {
        fprintf(stderr, "umdp_devio_release returned %d\n", ret);
        umdp_disconnect(connection);
        return 1;
    }

    umdp_disconnect(connection);
    return 0;
}
