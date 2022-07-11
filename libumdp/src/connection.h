#ifndef UMDP_CONNECTION_H
#define UMDP_CONNECTION_H

#include <stddef.h>

#include "umdp.h"

enum devio_value_type {
    DEVIO_VALUE_NONE,
    DEVIO_VALUE_U8,
    DEVIO_VALUE_U16,
    DEVIO_VALUE_U32,
};

typedef struct  {
    enum devio_value_type type;
    union {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
    };
} devio_value;

struct umdp_connection {
    struct nl_sock* socket;
    char* received_echo;
    devio_value received_devio_value;
    irq_queue irq_queue;
};

void umdp_connection_init(umdp_connection* connection);

#endif  // UMDP_CONNECTION_H
