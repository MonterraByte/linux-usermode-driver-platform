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
    __UMDP_ATTR_MAX,
};
#define UMDP_ATTR_MAX (__UMDP_ATTR_MAX - 1)

/* commands */
enum {
    UMDP_CMD_UNSPEC = 0,
    UMDP_CMD_ECHO = 1,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

static int umdp_echo(struct sk_buff* skb, struct genl_info* info);

/* attribute policy */
static struct nla_policy umdp_genl_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_MSG] =
        {
            .type = NLA_NUL_STRING,
        },
};

/* operation definition */
static const struct genl_ops umdp_genl_ops[] = {
    {
        .cmd = UMDP_CMD_ECHO,
        .flags = 0,
        .policy = umdp_genl_policy,
        .doit = umdp_echo,
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

/* UMDP_CMD_ECHO handler */
static int umdp_echo(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received echo request\n");

    struct nlattr** attributes = info->attrs;
    struct nlattr* msg_attr = NULL;

    int i;
    for (i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        if (attributes[i] == NULL) {
            continue;
        }

        if (nla_type(attributes[i]) == UMDP_ATTR_MSG) {
            msg_attr = attributes[i];
            break;
        }
    }

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
