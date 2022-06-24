#include "connection.h"

void irq_queue_init(irq_queue* queue) {
    queue->size = 0;
    queue->head = 0;
    queue->tail = 0;
}

bool irq_queue_push(irq_queue* queue, uint32_t value) {
    if (queue->size == IRQ_QUEUE_SIZE) {
        return false;
    }

    queue->values[queue->tail] = value;
    queue->tail = (queue->tail + 1) % IRQ_QUEUE_SIZE;
    queue->size++;
    return true;
}

bool irq_queue_pop(irq_queue* queue, uint32_t* out) {
    if (queue->size == 0) {
        return false;
    }

    *out = queue->values[queue->head];
    queue->head = (queue->head + 1) % IRQ_QUEUE_SIZE;
    queue->size--;
    return true;
}

void umdp_connection_init(umdp_connection* connection) {
    connection->socket = NULL;
    connection->received_echo = NULL;
    connection->received_devio_value.type = DEVIO_VALUE_NONE;
    irq_queue_init(&connection->irq_queue);
}
