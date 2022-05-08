#include <linux/init.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

MODULE_DESCRIPTION("User mode driver platform");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joaquim Monteiro <joaquim.monteiro@protonmail.com>");

#define UMDP_GENL_NAME "UMDP"
#define UMDP_GENL_VERSION 1

/* attributes */
enum {
    UMDP_ATTR_UNSPEC = 0,
    UMDP_ATTR_MSG = 1,
    UMDP_ATTR_U8 = 2,
    UMDP_ATTR_U16 = 3,
    UMDP_ATTR_U32 = 4,
    UMDP_ATTR_U64 = 5,
    __UMDP_ATTR_MAX,
};
#define UMDP_ATTR_MAX (__UMDP_ATTR_MAX - 1)

/* commands */
enum {
    UMDP_CMD_UNSPEC = 0,
    UMDP_CMD_ECHO = 1,
    UMDP_CMD_DEVIO_READ = 2,
    UMDP_CMD_DEVIO_WRITE = 3,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

/* attribute policy */
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

static int umdp_echo(struct sk_buff* skb, struct genl_info* info);
static int umdp_devio_read(struct sk_buff* skb, struct genl_info* info);
static int umdp_devio_write(struct sk_buff* skb, struct genl_info* info);

/* operation definition */
static const struct genl_ops umdp_genl_ops[] = {
    {
        .cmd = UMDP_CMD_ECHO,
        .flags = 0,
        .policy = umdp_genl_echo_policy,
        .doit = umdp_echo,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_READ,
        .flags = 0,
        .policy = umdp_genl_devio_policy,
        .doit = umdp_devio_read,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_WRITE,
        .flags = 0,
        .policy = umdp_genl_devio_policy,
        .doit = umdp_devio_write,
        .dumpit = NULL,
    },
};

/* family definition */
static struct genl_family umdp_genl_family = {
    .name = UMDP_GENL_NAME,
    .version = UMDP_GENL_VERSION,
    .maxattr = UMDP_ATTR_MAX,
    .ops = umdp_genl_ops,
    .n_ops = ARRAY_SIZE(umdp_genl_ops),
    .module = THIS_MODULE,
};

static struct nlattr* find_attribute(struct nlattr** attributes, int type) {
    int i;
    for (i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        if (attributes[i] == NULL) {
            continue;
        }

        if (nla_type(attributes[i]) == type) {
            return attributes[i];
        }
    }
    return NULL;
}

/* UMDP_CMD_ECHO handler */
static int umdp_echo(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received echo request\n");

    struct nlattr* msg_attr = find_attribute(info->attrs, UMDP_ATTR_MSG);
    if (msg_attr == NULL) {
        printk(KERN_ERR "umdp: did not find message attribute in echo request\n");
        return -EINVAL;
    }

    struct sk_buff* reply = genlmsg_new(nla_total_size(nla_len(msg_attr)), GFP_KERNEL);
    if (reply == NULL) {
        printk(KERN_ERR "umdp: failed to allocate buffer for echo reply\n");
        return -ENOMEM;
    }

    void* reply_header = genlmsg_put_reply(reply, info, &umdp_genl_family, 0, UMDP_CMD_ECHO);
    if (reply_header == NULL) {
        nlmsg_free(reply);
        printk(KERN_ERR "umdp: failed to add the generic netlink header to the echo reply\n");
        return -EMSGSIZE;
    }

    int ret = nla_put_string(reply, UMDP_ATTR_MSG, nla_data(msg_attr));
    if (ret != 0) {
        nlmsg_free(reply);
        printk(KERN_ERR "umdp: failed to write string to the echo reply\n");
        return ret;
    }

    genlmsg_end(reply, reply_header);
    ret = genlmsg_reply(reply, info);
    if (ret != 0) {
        printk(KERN_ERR "umdp: failed to send echo reply\n");
        return ret;
    }

    printk(KERN_DEBUG "umdp: sent echo reply\n");
    return 0;
}

static int umdp_devio_read(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received device IO read request\n");

    struct nlattr* port_attr = find_attribute(info->attrs, UMDP_ATTR_U64);
    if (port_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO read request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *(u64*) nla_data(port_attr);

    struct nlattr* type_attr = find_attribute(info->attrs, UMDP_ATTR_U8);
    if (type_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO read request: type attribute is missing\n");
        return -EINVAL;
    }

    int reply_size;
    switch (*(u8*) nla_data(type_attr)) {
        case UMDP_ATTR_U8:
            reply_size = sizeof(u8);
            break;
        case UMDP_ATTR_U16:
            reply_size = sizeof(u16);
            break;
        case UMDP_ATTR_U32:
            reply_size = sizeof(u32);
            break;
        default:
            printk(KERN_ERR "umdp: invalid device IO read request: invalid type\n");
            return -EINVAL;
    }

    struct sk_buff* reply = genlmsg_new(nla_total_size(reply_size), GFP_KERNEL);
    if (reply == NULL) {
        printk(KERN_ERR "umdp: failed to allocate buffer for device IO read reply\n");
        return -ENOMEM;
    }

    void* reply_header = genlmsg_put_reply(reply, info, &umdp_genl_family, 0, UMDP_CMD_DEVIO_READ);
    if (reply_header == NULL) {
        nlmsg_free(reply);
        printk(KERN_ERR "umdp: failed to add the generic netlink header to the device IO read reply\n");
        return -EMSGSIZE;
    }

    int ret;
    switch (reply_size) {
        case sizeof(u8): {
            u8 value = inb(port);
            printk(KERN_DEBUG "umdp: read %u (%x) from port %llu\n", value, value, port);
            ret = nla_put_u8(reply, UMDP_ATTR_U8, value);
            break;
        }
        case sizeof(u16): {
            u16 value = inw(port);
            printk(KERN_DEBUG "umdp: read %u (%x) from port %llu\n", value, value, port);
            ret = nla_put_u16(reply, UMDP_ATTR_U16, value);
            break;
        }
        case sizeof(u32): {
            u32 value = inl(port);
            printk(KERN_DEBUG "umdp: read %u (%x) from port %llu\n", value, value, port);
            ret = nla_put_u32(reply, UMDP_ATTR_U32, value);
            break;
        }
        default:
            printk(KERN_ERR "umdp: BUG! This code should be unreachable.\n");
            nlmsg_free(reply);
            return -EINVAL;
    }
    if (ret != 0) {
        nlmsg_free(reply);
        printk(KERN_ERR "umdp: failed to write value to reply\n");
        return ret;
    }

    genlmsg_end(reply, reply_header);
    ret = genlmsg_reply(reply, info);
    if (ret != 0) {
        printk(KERN_ERR "umdp: failed to send device IO read reply\n");
        return ret;
    }

    printk(KERN_DEBUG "umdp: sent device IO read reply\n");
    return 0;
}

static int umdp_devio_write(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received device IO write request\n");

    struct nlattr* port_attr = find_attribute(info->attrs, UMDP_ATTR_U64);
    if (port_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO write request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *((u64*) nla_data(port_attr));

    int i;
    for (i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        if (info->attrs[i] == NULL) {
            continue;
        }

        switch (nla_type(info->attrs[i])) {
            case UMDP_ATTR_U8: {
                u8 value = *((u8*) nla_data(info->attrs[i]));
                printk(KERN_DEBUG "umdp: writing %u (%x) to port %llu\n", value, value, port);
                outb(value, port);
                return 0;
            }
            case UMDP_ATTR_U16: {
                u16 value = *((u16*) nla_data(info->attrs[i]));
                printk(KERN_DEBUG "umdp: writing %u (%x) to port %llu\n", value, value, port);
                outw(value, port);
                return 0;
            }
            case UMDP_ATTR_U32: {
                u32 value = *((u32*) nla_data(info->attrs[i]));
                printk(KERN_DEBUG "umdp: writing %u (%x) to port %llu\n", value, value, port);
                outl(value, port);
                return 0;
            }
            default:
                break;
        }
    }

    printk(KERN_ERR "umdp: invalid device IO write request: value attribute is missing\n");
    return -EINVAL;
}

static int umdp_init(void) {
    int ret = genl_register_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to register netlink family\n");
        return ret;
    }

    printk(KERN_INFO "umdp: Registered netlink kernel family (id: %d)\n", umdp_genl_family.id);
    return 0;
}

static void umdp_exit(void) {
    int ret = genl_unregister_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to unregister netlink family\n");
        return;
    }

    printk(KERN_INFO "umdp: Unregistered netlink family\n");
}

module_init(umdp_init);
module_exit(umdp_exit);
