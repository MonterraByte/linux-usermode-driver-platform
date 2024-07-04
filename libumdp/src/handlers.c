#include "handlers.h"

#include <stdbool.h>

#include "connection.h"
#include "error.h"
#include "protocol.h"

static struct nlattr* find_attribute(struct nlattr** attributes, int type) {
    struct nlattr* type_attr = attributes[type];
    if (type_attr != NULL && nla_type(type_attr) == type) {
        return type_attr;
    }
    return NULL;
}

int umdp_connect_handler(__attribute__((unused)) struct nl_cache_ops* _cache_ops,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    umdp_connection* connection = arg;

    struct nlattr* result_attr = find_attribute(info->attrs, UMDP_ATTR_CONNECT_REPLY);
    if (result_attr == NULL) {
        print_err("received connect reply without a result attribute\n");
        return NL_SKIP;
    }

    uint8_t result = *((uint8_t*) nla_data(result_attr));
    connection->connect_command_result = result == 1 ? CONNECT_RESULT_SUCCESS : CONNECT_RESULT_FAILURE;
    return NL_SKIP;
}

int umdp_devio_read_handler(__attribute__((unused)) struct nl_cache_ops* _cache_ops,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    umdp_connection* connection = arg;

    bool found_attribute = false;
    for (int i = 0; i < UMDP_ATTR_DEVIO_READ_MAX + 1; i++) {
        struct nlattr* attr = info->attrs[i];
        if (attr == NULL) {
            continue;
        }

        switch (nla_type(attr)) {
            case UMDP_ATTR_DEVIO_READ_REPLY_U8: {
                connection->received_devio_value.type = DEVIO_VALUE_U8;
                connection->received_devio_value.u8 = *((uint8_t*) nla_data(attr));
                found_attribute = true;
                break;
            }
            case UMDP_ATTR_DEVIO_READ_REPLY_U16: {
                connection->received_devio_value.type = DEVIO_VALUE_U16;
                connection->received_devio_value.u16 = *((uint16_t*) nla_data(attr));
                found_attribute = true;
                break;
            }
            case UMDP_ATTR_DEVIO_READ_REPLY_U32: {
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

int umdp_interrupt_handler(__attribute__((unused)) struct nl_cache_ops* _unused,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    umdp_connection* connection = arg;

    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_INTERRUPT_IRQ);
    if (irq_attr == NULL) {
        print_err("received an interrupt notification without an IRQ attribute\n");
        return NL_SKIP;
    }

    uint32_t irq = *((uint32_t*) nla_data(irq_attr));
    if (!is_subscribed_to_irq(connection, irq)) {
        return NL_SKIP;
    }

    if (!irq_queue_push(&connection->irq_queue, irq)) {
        print_err("IRQ queue is full, discarding received IRQ\n");
    }

    return NL_SKIP;
}
