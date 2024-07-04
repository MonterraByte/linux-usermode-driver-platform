#include "protocol-family.h"

#include <assert.h>

#include "handlers.h"
#include "protocol.h"

static struct nla_policy umdp_genl_connect_policy[UMDP_ATTR_CONNECT_MAX + 1] = {
    [UMDP_ATTR_CONNECT_PID] =
        {
            .type = NLA_S32,
        },
    [UMDP_ATTR_CONNECT_REPLY] =
        {
            .type = NLA_U8,
        },
};
static_assert(sizeof(pid_t) == sizeof(uint32_t), "sizeof(pid_t) == sizeof(uint32_t)");

static struct nla_policy umdp_genl_devio_read_policy[UMDP_ATTR_DEVIO_READ_MAX + 1] = {
    [UMDP_ATTR_DEVIO_READ_PORT] =
        {
            .type = NLA_U64,
        },
    [UMDP_ATTR_DEVIO_READ_TYPE] =
        {
            .type = NLA_U8,
        },
    [UMDP_ATTR_DEVIO_READ_REPLY_U8] =
        {
            .type = NLA_U8,
        },
    [UMDP_ATTR_DEVIO_READ_REPLY_U16] =
        {
            .type = NLA_U16,
        },
    [UMDP_ATTR_DEVIO_READ_REPLY_U32] =
        {
            .type = NLA_U32,
        },
};

static struct nla_policy umdp_genl_devio_write_policy[UMDP_ATTR_DEVIO_WRITE_MAX + 1] = {
    [UMDP_ATTR_DEVIO_WRITE_PORT] =
        {
            .type = NLA_U64,
        },
    [UMDP_ATTR_DEVIO_WRITE_VALUE_U8] =
        {
            .type = NLA_U8,
        },
    [UMDP_ATTR_DEVIO_WRITE_VALUE_U16] =
        {
            .type = NLA_U16,
        },
    [UMDP_ATTR_DEVIO_WRITE_VALUE_U32] =
        {
            .type = NLA_U32,
        },
};

static struct nla_policy umdp_genl_devio_request_policy[UMDP_ATTR_DEVIO_REQUEST_MAX + 1] = {
    [UMDP_ATTR_DEVIO_REQUEST_START] =
        {
            .type = NLA_U64,
        },
    [UMDP_ATTR_DEVIO_REQUEST_SIZE] =
        {
            .type = NLA_U64,
        },
};

static struct nla_policy umdp_genl_interrupt_policy[UMDP_ATTR_INTERRUPT_MAX + 1] = {
    [UMDP_ATTR_INTERRUPT_IRQ] =
        {
            .type = NLA_U32,
        },
};

static struct genl_cmd umdp_cmds[] = {
    {
        .c_id = UMDP_CMD_CONNECT,
        .c_name = "UMDP_CMD_CONNECT",
        .c_maxattr = UMDP_ATTR_CONNECT_MAX,
        .c_attr_policy = umdp_genl_connect_policy,
        .c_msg_parser = umdp_connect_handler,
    },
    {
        .c_id = UMDP_CMD_DEVIO_READ,
        .c_name = "UMDP_CMD_DEVIO_READ",
        .c_maxattr = UMDP_ATTR_DEVIO_READ_MAX,
        .c_attr_policy = umdp_genl_devio_read_policy,
        .c_msg_parser = umdp_devio_read_handler,
    },
    {
        .c_id = UMDP_CMD_DEVIO_WRITE,
        .c_name = "UMDP_CMD_DEVIO_WRITE",
        .c_maxattr = UMDP_ATTR_DEVIO_WRITE_MAX,
        .c_attr_policy = umdp_genl_devio_write_policy,
    },
    {
        .c_id = UMDP_CMD_DEVIO_REQUEST,
        .c_name = "UMDP_CMD_DEVIO_REQUEST",
        .c_maxattr = UMDP_ATTR_DEVIO_REQUEST_MAX,
        .c_attr_policy = umdp_genl_devio_request_policy,
    },
    {
        .c_id = UMDP_CMD_DEVIO_RELEASE,
        .c_name = "UMDP_CMD_DEVIO_RELEASE",
        .c_maxattr = UMDP_ATTR_DEVIO_REQUEST_MAX,
        .c_attr_policy = umdp_genl_devio_request_policy,
    },
    {
        .c_id = UMDP_CMD_INTERRUPT_NOTIFICATION,
        .c_name = "UMDP_CMD_INTERRUPT_NOTIFICATION",
        .c_maxattr = UMDP_ATTR_INTERRUPT_MAX,
        .c_attr_policy = umdp_genl_interrupt_policy,
        .c_msg_parser = umdp_interrupt_handler,
    },
    {
        .c_id = UMDP_CMD_INTERRUPT_SUBSCRIBE,
        .c_name = "UMDP_CMD_INTERRUPT_SUBSCRIBE",
        .c_maxattr = UMDP_ATTR_INTERRUPT_MAX,
        .c_attr_policy = umdp_genl_interrupt_policy,
    },
    {
        .c_id = UMDP_CMD_INTERRUPT_UNSUBSCRIBE,
        .c_name = "UMDP_CMD_INTERRUPT_UNSUBSCRIBE",
        .c_maxattr = UMDP_ATTR_INTERRUPT_MAX,
        .c_attr_policy = umdp_genl_interrupt_policy,
    },
};

struct genl_ops umdp_family = {
    .o_name = UMDP_GENL_NAME,
    .o_cmds = umdp_cmds,
    .o_ncmds = sizeof(umdp_cmds) / sizeof(struct genl_cmd),
};
