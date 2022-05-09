#include "umdp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/socket.h>

#include "error.h"
#include "handlers.h"
#include "protocol.h"

static struct nla_policy umdp_genl_echo_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_MSG] =
        {
            .type = NLA_NUL_STRING,
        },
};

static struct nla_policy umdp_genl_devio_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_U8] =
        {
            .type = NLA_U8,
        },
    [UMDP_ATTR_U16] =
        {
            .type = NLA_U16,
        },
    [UMDP_ATTR_U32] =
        {
            .type = NLA_U32,
        },
    [UMDP_ATTR_U64] =
        {
            .type = NLA_U64,
        },
};

static struct genl_cmd umdp_cmds[] = {
    {
        .c_id = UMDP_CMD_ECHO,
        .c_name = "UMDP_CMD_ECHO",
        .c_maxattr = UMDP_ATTR_MAX,
        .c_attr_policy = umdp_genl_echo_policy,
        .c_msg_parser = umdp_echo_handler,
    },
    {
        .c_id = UMDP_CMD_DEVIO_READ,
        .c_name = "UMDP_CMD_DEVIO_READ",
        .c_maxattr = UMDP_ATTR_MAX,
        .c_attr_policy = umdp_genl_devio_policy,
        .c_msg_parser = umdp_devio_read_handler,
    },
    {
        .c_id = UMDP_CMD_DEVIO_WRITE,
        .c_name = "UMDP_CMD_DEVIO_WRITE",
        .c_maxattr = UMDP_ATTR_MAX,
        .c_attr_policy = umdp_genl_devio_policy,
    },
};

static struct genl_ops umdp_family = {
    .o_name = UMDP_GENL_NAME,
    .o_cmds = umdp_cmds,
    .o_ncmds = sizeof(umdp_cmds) / sizeof(struct genl_cmd),
};

struct umdp_connection {
    struct nl_sock* socket;
};

umdp_connection* umdp_connect() {
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

    connection->socket = nl_socket_alloc();
    if (connection->socket == NULL) {
        print_err("failed to allocate socket\n");
        goto socket_failure;
    }

    ret = nl_socket_modify_cb(connection->socket, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, NULL);
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

    return connection;

failure:
    nl_socket_free(connection->socket);
socket_failure:
    free(connection);
    return NULL;
}

void umdp_disconnect(umdp_connection* connection) {
    nl_socket_free(connection->socket);
    free(connection);
}

char* umdp_echo(umdp_connection* connection, char* string) {
    size_t string_length = strlen(string) + 1;

    struct nl_msg* msg = nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size((int) string_length));
    if (msg == NULL) {
        print_err("failed to allocate memory\n");
        return NULL;
    }

    if (genlmsg_put(
            msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST, UMDP_CMD_ECHO, UMDP_GENL_VERSION)
        == NULL) {
        print_err("failed to write netlink headers\n");
        goto msg_failure;
    }

    int ret = nla_put_string(msg, UMDP_ATTR_MSG, string);
    if (ret != 0) {
        printf_err("failed to write string: %s\n", nl_geterror(ret));
        goto msg_failure;
    }

    char* reply = NULL;
    ret = nl_socket_modify_cb(connection->socket, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, &reply);
    if (ret != 0) {
        printf_err("failed to register callback: %s\n", nl_geterror(ret));
        goto msg_failure;
    }

    ret = nl_send_auto(connection->socket, msg);
    if (ret < 0) {
        printf_err("failed to send message: %s\n", nl_geterror(ret));
        goto msg_failure;
    }
    nlmsg_free(msg);

    ret = nl_recvmsgs_default(connection->socket);
    if (ret != 0) {
        printf_err("failed to receive reply: %s\n", nl_geterror(ret));
        return NULL;
    }

    return reply;

msg_failure:
    nlmsg_free(msg);
    return NULL;
}

static int umdp_devio_read(umdp_connection* connection, uint64_t port, uint8_t type, void* out) {
    struct nl_msg* msg = nlmsg_alloc_size(
        NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(uint64_t)) + nla_total_size(sizeof(uint8_t)));
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

    int ret = nla_put_u64(msg, UMDP_ATTR_U64, port);
    if (ret != 0) {
        printf_err("failed to write port: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nla_put_u8(msg, UMDP_ATTR_U8, type);
    if (ret != 0) {
        printf_err("failed to write read size: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    ret = nl_socket_modify_cb(connection->socket, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, out);
    if (ret != 0) {
        printf_err("failed to register callback: %s\n", nl_geterror(ret));
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

    ret = nl_recvmsgs_default(connection->socket);
    if (ret != 0) {
        printf_err("failed to receive reply: %s\n", nl_geterror(ret));
        return ret;
    }

    return 0;
}

int umdp_devio_read_u8(umdp_connection* connection, uint64_t port, uint8_t* out) {
    return umdp_devio_read(connection, port, UMDP_ATTR_U8, (void*) out);
}

int umdp_devio_read_u16(umdp_connection* connection, uint64_t port, uint16_t* out) {
    return umdp_devio_read(connection, port, UMDP_ATTR_U16, (void*) out);
}

int umdp_devio_read_u32(umdp_connection* connection, uint64_t port, uint32_t* out) {
    return umdp_devio_read(connection, port, UMDP_ATTR_U32, (void*) out);
}

static int umdp_devio_write(umdp_connection* connection, uint64_t port, uint8_t type, void* value) {
    int value_size;
    switch (type) {
        case UMDP_ATTR_U8:
            value_size = sizeof(uint8_t);
            break;
        case UMDP_ATTR_U16:
            value_size = sizeof(uint16_t);
            break;
        case UMDP_ATTR_U32:
            value_size = sizeof(uint32_t);
            break;
        default:
            return EINVAL;
    }

    struct nl_msg* msg =
        nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(uint64_t)) + nla_total_size(value_size));
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

    int ret = nla_put_u64(msg, UMDP_ATTR_U64, port);
    if (ret != 0) {
        printf_err("failed to write port: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        return ret;
    }

    switch (type) {
        case UMDP_ATTR_U8:
            ret = nla_put_u8(msg, UMDP_ATTR_U8, *((uint8_t*) value));
            break;
        case UMDP_ATTR_U16:
            ret = nla_put_u16(msg, UMDP_ATTR_U16, *((uint16_t*) value));
            break;
        case UMDP_ATTR_U32:
            ret = nla_put_u32(msg, UMDP_ATTR_U32, *((uint32_t*) value));
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
    return umdp_devio_write(connection, port, UMDP_ATTR_U8, &value);
}

int umdp_devio_write_u16(umdp_connection* connection, uint64_t port, uint16_t value) {
    return umdp_devio_write(connection, port, UMDP_ATTR_U16, &value);
}

int umdp_devio_write_u32(umdp_connection* connection, uint64_t port, uint32_t value) {
    return umdp_devio_write(connection, port, UMDP_ATTR_U32, &value);
}
