#include "connection.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netlink/socket.h>

#include "error.h"

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
    connection->owner_pid = getpid();
    connection->connect_command_result = CONNECT_RESULT_NONE;
    connection->subscribed_irqs = NULL;
    connection->subscribed_irq_count = 0;
    connection->received_devio_value.type = DEVIO_VALUE_NONE;
    irq_queue_init(&connection->irq_queue);
    connection->mem_fd = -1;
}

void umdp_connection_destroy(umdp_connection* connection) {
    nl_socket_free(connection->socket);
    free(connection->subscribed_irqs);
    if (connection->mem_fd >= 0) {
        close(connection->mem_fd);
    }
}

void umdp_connection_add_irq(umdp_connection* connection, uint32_t irq) {
    if (is_subscribed_to_irq(connection, irq)) {
        return;
    }

    connection->subscribed_irq_count++;
    connection->subscribed_irqs = realloc(connection->subscribed_irqs, connection->subscribed_irq_count);
    if (connection->subscribed_irqs == NULL) {
        print_err("failed to allocate memory");
        abort();
    }

    connection->subscribed_irqs[connection->subscribed_irq_count - 1] = irq;
}

void umdp_connection_remove_irq(umdp_connection* connection, uint32_t irq) {
    for (size_t i = 0; i < connection->subscribed_irq_count; i++) {
        if (connection->subscribed_irqs[i] == irq) {
            for (size_t j = i + 1; j < connection->subscribed_irq_count; j++) {
                connection->subscribed_irqs[j - 1] = connection->subscribed_irqs[j];
            }

            connection->subscribed_irq_count--;
            connection->subscribed_irqs = realloc(connection->subscribed_irqs, connection->subscribed_irq_count);
            if (connection->subscribed_irqs == NULL && connection->subscribed_irq_count != 0) {
                print_err("failed to allocate memory");
                abort();
            }
            break;
        }
    }
}

bool is_subscribed_to_irq(umdp_connection* connection, uint32_t irq) {
    if (connection->subscribed_irqs == NULL) {
        return false;
    }

    for (size_t i = 0; i < connection->subscribed_irq_count; i++) {
        if (connection->subscribed_irqs[i] == irq) {
            return true;
        }
    }
    return false;
}

int umdp_open_mem_if_unopened(umdp_connection* connection) {
    if (connection->mem_fd >= 0) {
        return 0;
    }

    connection->mem_fd = open("/dev/umdp-mem", O_RDWR);
    if (connection->mem_fd < 0) {
        int ret = errno;
        printf_err("failed to open /dev/umdp-mem: %s\n", strerror(ret));
        return ret;
    }

    return 0;
}

void umdp_ensure_original_pid(umdp_connection* connection) {
    if (getpid() != connection->owner_pid) {
        print_err(
            "tried to use a umdp_connection from a process other than the one that created it, which is not "
            "allowed.\n");
        abort();
    }
}
