#include "handlers.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "connection.h"
#include "error.h"
#include "protocol.h"

static struct nlattr* find_attribute(struct nlattr** attributes, int type) {
    for (int i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        struct nlattr* attribute = attributes[i];
        if (attribute == NULL) {
            continue;
        }

        if (nla_type(attribute) == type) {
            return attribute;
        }
    }
    return NULL;
}

int umdp_echo_handler(__attribute__((unused)) struct nl_cache_ops* _cache_ops,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    umdp_connection* connection = arg;

    struct nlattr* msg_attr = find_attribute(info->attrs, UMDP_ATTR_MSG);
    if (msg_attr == NULL) {
        print_err("received echo reply without a message attribute\n");
        return NL_SKIP;
    }

    size_t message_length = nla_len(msg_attr);
    connection->received_echo = malloc(message_length);
    if (connection->received_echo == NULL) {
        print_err("failed to allocate memory\n");
        return NL_STOP;
    }

    memcpy(connection->received_echo, nla_data(msg_attr), message_length);
    return NL_SKIP;
}

int umdp_devio_read_handler(__attribute__((unused)) struct nl_cache_ops* _cache_ops,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    umdp_connection* connection = arg;

    bool found_attribute = false;
    for (int i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        struct nlattr* attr = info->attrs[i];
        if (attr == NULL) {
            continue;
        }

        switch (nla_type(attr)) {
            case UMDP_ATTR_U8: {
                connection->received_devio_value.type = DEVIO_VALUE_U8;
                connection->received_devio_value.u8 = *((uint8_t*) nla_data(attr));
                found_attribute = true;
                break;
            }
            case UMDP_ATTR_U16: {
                connection->received_devio_value.type = DEVIO_VALUE_U16;
                connection->received_devio_value.u16 = *((uint16_t*) nla_data(attr));
                found_attribute = true;
                break;
            }
            case UMDP_ATTR_U32: {
                connection->received_devio_value.type = DEVIO_VALUE_U32;
                connection->received_devio_value.u32 = *((uint32_t*) nla_data(attr));
                found_attribute = true;
                break;
            }
            default:
                break;
        }

        if (found_attribute) {
            break;
        }
    }

    if (!found_attribute) {
        print_err("received device IO read reply without a value attribute\n");
    }

    return NL_SKIP;
}

int umdp_interrupt_handler(__attribute__((unused)) struct nl_cache_ops* _unused, __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    umdp_connection* connection = arg;

    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_MSG);
    if (irq_attr == NULL) {
        print_err("received an interrupt notification without an IRQ attribute\n");
        return NL_SKIP;
    }

    uint32_t irq = *((uint32_t*) nla_data(irq_attr));
    if (!is_subscribed_to_irq(connection, irq)) {
        return NL_SKIP;
    }

    if (!irq_queue_push(&connection->irq_queue, irq)) {
        print_err("IRQ queue is full, discarding received IRQ");
    }

    return NL_SKIP;
}
