#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umdp.h>

typedef enum {
    READ,
    WRITE,
} operation;

typedef enum {
    U8,
    U16,
    U32,
} length;

char* argv0;
void print_usage() {
    fprintf(stderr, "USAGE: %s mode length port [value]\nmode: read, write\nlength: 1, 2, 4\n", argv0);
    exit(1);
}

void parse_args(int argc, char* argv[], operation* op, length* len, uint64_t* port, unsigned long* value) {
    if (argc < 2) {
        print_usage();
    }

    if (strcmp(argv[1], "read") == 0) {
        *op = READ;
        if (argc != 4) {
            print_usage();
        }
    } else if (strcmp(argv[1], "write") == 0) {
        *op = WRITE;
        if (argc != 5) {
            print_usage();
        }

        // strtoul can't detect 0. Amazing.
        if (strcmp(argv[4], "0") == 0) {
            *value = 0;
        } else {
            *value = strtoul(argv[4], NULL, 0);
            if (*value == 0 || *value == ULONG_MAX) {
                print_usage();
            }
        }
    } else {
        print_usage();
    }

    switch (strtol(argv[2], NULL, 0)) {
        case 1:
            *len = U8;
            break;
        case 2:
            *len = U16;
            break;
        case 4:
            *len = U32;
            break;
        default:
            print_usage();
    }

    *port = strtoul(argv[3], NULL, 0);
    if (*port == 0 || *port == ULONG_MAX) {
        print_usage();
    }
}

void devio_read(umdp_connection* connection, uint64_t port, length len) {
    int ret = -1;
    switch (len) {
        case U8: {
            uint8_t value;
            ret = umdp_devio_read_u8(connection, port, &value);
            if (ret == 0) {
                printf("%u (%x)\n", value, value);
            }
            break;
        }
        case U16: {
            uint16_t value;
            ret = umdp_devio_read_u16(connection, port, &value);
            if (ret == 0) {
                printf("%u (%x)\n", value, value);
            }
            break;
        }
        case U32: {
            uint32_t value;
            ret = umdp_devio_read_u32(connection, port, &value);
            if (ret == 0) {
                printf("%u (%x)\n", value, value);
            }
            break;
        }
    }

    if (ret != 0) {
        fprintf(stderr, "read failed with code %d\n", ret);
    }
}

void devio_write(umdp_connection* connection, uint64_t port, length len, unsigned long value) {
    int ret = -1;
    switch (len) {
        case U8:
            if (value > UINT8_MAX) {
                print_usage();
            }
            ret = umdp_devio_write_u8(connection, port, (uint8_t) value);
            break;
        case U16:
            if (value > UINT16_MAX) {
                print_usage();
            }
            ret = umdp_devio_write_u16(connection, port, (uint16_t) value);
            break;
        case U32:
            if (value > UINT32_MAX) {
                print_usage();
            }
            ret = umdp_devio_write_u32(connection, port, (uint32_t) value);
            break;
    }

    if (ret != 0) {
        fprintf(stderr, "write failed with code %d\n", ret);
    }
}

int main(int argc, char* argv[]) {
    argv0 = argv[0];

    operation op;
    length len;
    uint64_t port;
    unsigned long value;
    parse_args(argc, argv, &op, &len, &port, &value);

    umdp_connection* connection = umdp_connect();
    if (connection == NULL) {
        fprintf(stderr, "umdp_init returned NULL\n");
        return 1;
    }

    switch (op) {
        case READ:
            devio_read(connection, port, len);
            break;
        case WRITE: {
            devio_write(connection, port, len, value);
            break;
        }
    }

    umdp_disconnect(connection);
    return 0;
}
