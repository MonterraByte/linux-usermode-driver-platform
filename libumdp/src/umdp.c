#include "umdp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/socket.h>

#include "connection.h"
#include "error.h"
#include "protocol.h"
#include "protocol-family.h"

static int umdp_connect_command(umdp_connection* connection) {
    struct nl_msg* msg = nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(pid_t)));
    if (msg == NULL) {
        print_err("failed to allocate memory\n");
        return ENOMEM;
    }

    if (genlmsg_put(
            msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST, UMDP_CMD_CONNECT, UMDP_GENL_VERSION)
        == NULL) {
        print_err("failed to write netlink headers\n");
        nlmsg_free(msg);
        return -NLE_NOMEM;
    }

    int ret = nla_put_s32(msg, UMDP_ATTR_CONNECT_PID, connection->owner_pid);
    if (ret != 0) {
        printf_err("failed to write pid: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(connection->socket, msg);
    nlmsg_free(msg);
    if (ret < 0) {
        printf_err("failed to send device IO write request: %s\n", nl_geterror(ret));
        return ret;
    }

    do {
        ret = nl_recvmsgs_default(connection->socket);
        if (ret != 0) {
            printf_err("failed to receive reply: %s\n", nl_geterror(ret));
            return ret;
        }
    } while (connection->connect_command_result == CONNECT_RESULT_NONE);

    if (connection->connect_command_result == CONNECT_RESULT_FAILURE) {
        print_err(
            "failed to register process (either it was already registered, or the kernel module encountered an "
            "error)\n");
        return -NLE_FAILURE;
    }

    return 0;
}

umdp_connection* umdp_connect(void) {
    int ret = genl_register_family(&umdp_family);
    if (ret != 0 && ret != -NLE_EXIST) {
        printf_err("failed to register generic netlink family: %s\n", nl_geterror(ret));
        return NULL;
    }

    umdp_connection* connection = malloc(sizeof(umdp_connection));
    if (connection == NULL) {
        print_err("failed to allocate memory\n");
        return NULL;
    }
    umdp_connection_init(connection);

    connection->socket = nl_socket_alloc();
    if (connection->socket == NULL) {
        print_err("failed to allocate socket\n");
        goto failure;
    }

    // Disable seq number checks to be able to receive multicast messages
    nl_socket_disable_seq_check(connection->socket);

    ret = nl_socket_modify_cb(connection->socket, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, connection);
    if (ret != 0) {
        printf_err("failed to register callback: %s\n", nl_geterror(ret));
        goto failure;
    }

    // Set the socket to talk to the kernel, which has port 0
    nl_socket_set_peer_port(connection->socket, 0);

    ret = genl_connect(connection->socket);
    if (ret != 0) {
        printf_err("failed to create and bind socket: %s\n", nl_geterror(ret));
        goto failure;
    }

    ret = genl_ops_resolve(connection->socket, &umdp_family);
    if (ret != 0) {
        printf_err("failed to resolve generic netlink family: %s\n", nl_geterror(ret));
        goto failure;
    }

    int interrupt_multicast_group =
        genl_ctrl_resolve_grp(connection->socket, UMDP_GENL_NAME, UMDP_GENL_INTERRUPT_MULTICAST_NAME);
    if (interrupt_multicast_group < 0) {
        printf_err("failed to resolve multicast group: %s\n", nl_geterror(interrupt_multicast_group));
        goto failure;
    }

    ret = nl_socket_add_membership(connection->socket, interrupt_multicast_group);
    if (ret != 0) {
        printf_err("failed to register to multicast group: %s\n", nl_geterror(ret));
        goto failure;
    }

    ret = umdp_connect_command(connection);
    if (ret != 0) {
        printf_err("failed to send connect command: %s\n", nl_geterror(ret));
        goto failure;
    }

    return connection;

failure:
    umdp_connection_destroy(connection);
    free(connection);
    return NULL;
}

void umdp_disconnect(umdp_connection* connection) {
    umdp_connection_destroy(connection);
    free(connection);
}

static int umdp_devio_read(umdp_connection* connection, uint64_t port, uint8_t type, void* out) {
    connection->received_devio_value.type = DEVIO_VALUE_NONE;

    struct nl_msg* msg =
        nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(port)) + nla_total_size(sizeof(type)));
    if (msg == NULL) {
        print_err("failed to allocate memory\n");
        return ENOMEM;
    }

    if (genlmsg_put(
            msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST, UMDP_CMD_DEVIO_READ, UMDP_GENL_VERSION)
        == NULL) {
        print_err("failed to write netlink headers\n");
        nlmsg_free(msg);
        return -NLE_NOMEM;
    }

    int ret = nla_put_u64(msg, UMDP_ATTR_DEVIO_READ_PORT, port);
    if (ret != 0) {
        printf_err("failed to write port: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nla_put_u8(msg, UMDP_ATTR_DEVIO_READ_TYPE, type);
    if (ret != 0) {
        printf_err("failed to write read size: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(connection->socket, msg);
    if (ret < 0) {
        printf_err("failed to send device IO read request: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }
    nlmsg_free(msg);

    while (connection->received_devio_value.type == DEVIO_VALUE_NONE) {
        ret = nl_recvmsgs_default(connection->socket);
        if (ret != 0) {
            printf_err("failed to receive reply: %s\n", nl_geterror(ret));
            return ret;
        }
    }

    if ((type == UMDP_ATTR_DEVIO_READ_REPLY_U8 && connection->received_devio_value.type != DEVIO_VALUE_U8)
        || (type == UMDP_ATTR_DEVIO_READ_REPLY_U16 && connection->received_devio_value.type != DEVIO_VALUE_U16)
        || (type == UMDP_ATTR_DEVIO_READ_REPLY_U32 && connection->received_devio_value.type != DEVIO_VALUE_U32)) {
        print_err("received value type does not match the expected type");
        return -1;
    }

    switch (type) {
        case UMDP_ATTR_DEVIO_READ_REPLY_U8:
            *((uint8_t*) out) = connection->received_devio_value.u8;
            break;
        case UMDP_ATTR_DEVIO_READ_REPLY_U16:
            *((uint16_t*) out) = connection->received_devio_value.u16;
            break;
        case UMDP_ATTR_DEVIO_READ_REPLY_U32:
            *((uint32_t*) out) = connection->received_devio_value.u32;
            break;
    }

    connection->received_devio_value.type = DEVIO_VALUE_NONE;
    return 0;
}

int umdp_devio_read_u8(umdp_connection* connection, uint64_t port, uint8_t* out) {
    return umdp_devio_read(connection, port, UMDP_ATTR_DEVIO_READ_REPLY_U8, (void*) out);
}

int umdp_devio_read_u16(umdp_connection* connection, uint64_t port, uint16_t* out) {
    return umdp_devio_read(connection, port, UMDP_ATTR_DEVIO_READ_REPLY_U16, (void*) out);
}

int umdp_devio_read_u32(umdp_connection* connection, uint64_t port, uint32_t* out) {
    return umdp_devio_read(connection, port, UMDP_ATTR_DEVIO_READ_REPLY_U32, (void*) out);
}

static int umdp_devio_write(umdp_connection* connection, uint64_t port, uint8_t type, void* value) {
    int value_size;
    switch (type) {
        case UMDP_ATTR_DEVIO_WRITE_VALUE_U8:
            value_size = sizeof(uint8_t);
            break;
        case UMDP_ATTR_DEVIO_WRITE_VALUE_U16:
            value_size = sizeof(uint16_t);
            break;
        case UMDP_ATTR_DEVIO_WRITE_VALUE_U32:
            value_size = sizeof(uint32_t);
            break;
        default:
            return EINVAL;
    }

    struct nl_msg* msg =
        nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(port)) + nla_total_size(value_size));
    if (msg == NULL) {
        print_err("failed to allocate memory\n");
        return ENOMEM;
    }

    if (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST | NLM_F_ACK,
            UMDP_CMD_DEVIO_WRITE, UMDP_GENL_VERSION)
        == NULL) {
        print_err("failed to write netlink headers\n");
        nlmsg_free(msg);
        return -NLE_NOMEM;
    }

    int ret = nla_put_u64(msg, UMDP_ATTR_DEVIO_WRITE_PORT, port);
    if (ret != 0) {
        printf_err("failed to write port: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    switch (type) {
        case UMDP_ATTR_DEVIO_WRITE_VALUE_U8:
            ret = nla_put_u8(msg, UMDP_ATTR_DEVIO_WRITE_VALUE_U8, *((uint8_t*) value));
            break;
        case UMDP_ATTR_DEVIO_WRITE_VALUE_U16:
            ret = nla_put_u16(msg, UMDP_ATTR_DEVIO_WRITE_VALUE_U16, *((uint16_t*) value));
            break;
        case UMDP_ATTR_DEVIO_WRITE_VALUE_U32:
            ret = nla_put_u32(msg, UMDP_ATTR_DEVIO_WRITE_VALUE_U32, *((uint32_t*) value));
            break;
        default:
            return EINVAL;
    }
    if (ret != 0) {
        printf_err("failed to write value: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(connection->socket, msg);
    nlmsg_free(msg);
    if (ret < 0) {
        printf_err("failed to send device IO write request: %s\n", nl_geterror(ret));
        return ret;
    }

    ret = nl_wait_for_ack(connection->socket);
    if (ret != 0) {
        printf_err("failed to receive ACK: %s\n", nl_geterror(ret));
        return ret;
    }

    return 0;
}

int umdp_devio_write_u8(umdp_connection* connection, uint64_t port, uint8_t value) {
    return umdp_devio_write(connection, port, UMDP_ATTR_DEVIO_WRITE_VALUE_U8, &value);
}

int umdp_devio_write_u16(umdp_connection* connection, uint64_t port, uint16_t value) {
    return umdp_devio_write(connection, port, UMDP_ATTR_DEVIO_WRITE_VALUE_U16, &value);
}

int umdp_devio_write_u32(umdp_connection* connection, uint64_t port, uint32_t value) {
    return umdp_devio_write(connection, port, UMDP_ATTR_DEVIO_WRITE_VALUE_U32, &value);
}

static int umdp_devio_region_request(umdp_connection* connection, uint64_t start, uint64_t size, uint8_t command) {
    if (size == 0) {
        print_err("size cannot be 0\n");
        return EINVAL;
    }

    struct nl_msg* msg =
        nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(start)) + nla_total_size(sizeof(size)));
    if (msg == NULL) {
        print_err("failed to allocate memory\n");
        return ENOMEM;
    }

    if (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST, command, UMDP_GENL_VERSION)
        == NULL) {
        print_err("failed to write netlink headers\n");
        nlmsg_free(msg);
        return -NLE_NOMEM;
    }

    int ret = nla_put_u64(msg, UMDP_ATTR_DEVIO_REQUEST_START, start);
    if (ret != 0) {
        printf_err("failed to write start value: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nla_put_u64(msg, UMDP_ATTR_DEVIO_REQUEST_SIZE, size);
    if (ret != 0) {
        printf_err("failed to write size value: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(connection->socket, msg);
    nlmsg_free(msg);
    if (ret < 0) {
        printf_err("failed to send IO region request: %s\n", nl_geterror(ret));
        return ret;
    }

    ret = nl_wait_for_ack(connection->socket);
    if (ret != 0) {
        printf_err("failed to receive ACK: %s\n", nl_geterror(ret));
        return ret;
    }

    return 0;
}

int umdp_devio_request(umdp_connection* connection, uint64_t start, uint64_t size) {
    return umdp_devio_region_request(connection, start, size, UMDP_CMD_DEVIO_REQUEST);
}

int umdp_devio_release(umdp_connection* connection, uint64_t start, uint64_t size) {
    return umdp_devio_region_request(connection, start, size, UMDP_CMD_DEVIO_RELEASE);
}

static int umdp_interrupt_subscription_request(umdp_connection* connection, uint32_t irq, uint8_t command) {
    struct nl_msg* msg = nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(irq)));
    if (msg == NULL) {
        print_err("failed to allocate memory\n");
        return ENOMEM;
    }

    if (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST, command, UMDP_GENL_VERSION)
        == NULL) {
        print_err("failed to write netlink headers\n");
        nlmsg_free(msg);
        return -NLE_NOMEM;
    }

    int ret = nla_put_u32(msg, UMDP_ATTR_INTERRUPT_IRQ, irq);
    if (ret != 0) {
        printf_err("failed to write IRQ value: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_send_auto(connection->socket, msg);
    nlmsg_free(msg);
    if (ret < 0) {
        printf_err("failed to send interrupt subscription request: %s\n", nl_geterror(ret));
        return ret;
    }

    ret = nl_wait_for_ack(connection->socket);
    if (ret != 0) {
        printf_err("failed to receive ACK: %s\n", nl_geterror(ret));
        return ret;
    }

    if (command == UMDP_CMD_INTERRUPT_SUBSCRIBE) {
        umdp_connection_add_irq(connection, irq);
    } else {
        umdp_connection_remove_irq(connection, irq);
    }
    return 0;
}

int umdp_interrupt_subscribe(umdp_connection* connection, uint32_t irq) {
    return umdp_interrupt_subscription_request(connection, irq, UMDP_CMD_INTERRUPT_SUBSCRIBE);
}

int umdp_interrupt_unsubscribe(umdp_connection* connection, uint32_t irq) {
    return umdp_interrupt_subscription_request(connection, irq, UMDP_CMD_INTERRUPT_UNSUBSCRIBE);
}

int umdp_receive_interrupt(umdp_connection* connection, uint32_t* out) {
    if (connection->subscribed_irq_count == 0) {
        print_err("not subscribed to any IRQ lines");
        return ENOENT;
    }

    while (!irq_queue_pop(&connection->irq_queue, out)) {
        int ret = nl_recvmsgs_default(connection->socket);
        if (ret != 0) {
            printf_err("failed to receive reply: %s\n", nl_geterror(ret));
            return ret;
        }
    }
    return 0;
}

int umdp_mmap_physical(umdp_connection* connection, off_t start, size_t size, void** out) {
    if (out == NULL) {
        print_err("out parameter is NULL\n");
        return EINVAL;
    }
    *out = NULL;

    if (size == 0) {
        print_err("size parameter is 0\n");
        return EINVAL;
    }

    int ret = umdp_open_mem_if_unopened(connection);
    if (ret != 0) {
        return ret;
    }

    void* result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, connection->mem_fd, start);
    if (result == MAP_FAILED) {
        ret = errno;
        printf_err("mmap failed: %s\n", strerror(ret));
        return ret;
    }

    *out = result;
    return 0;
}

const char* umdp_strerror(int error) {
    if (error < 0) {
        return nl_geterror(error);
    } else if (error > 0) {
        return strerror(error);
    } else {
        return "";
    }
}
