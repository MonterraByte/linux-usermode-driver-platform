#ifndef UMDP_CONNECTION_H
#define UMDP_CONNECTION_H

#include <stdbool.h>
#include <stddef.h>

#include "umdp.h"

#define IRQ_QUEUE_SIZE 32

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

typedef struct  {
    size_t size;
    size_t head;
    size_t tail;
    uint32_t values[IRQ_QUEUE_SIZE];
} irq_queue;

void irq_queue_init(irq_queue* queue);
bool irq_queue_push(irq_queue* queue, uint32_t value);
bool irq_queue_pop(irq_queue* queue, uint32_t* out);

struct umdp_connection {
    struct nl_sock* socket;
    char* received_echo;
    devio_value received_devio_value;
    irq_queue irq_queue;
};

void umdp_connection_init(umdp_connection* connection);

#endif  // UMDP_CONNECTION_H
