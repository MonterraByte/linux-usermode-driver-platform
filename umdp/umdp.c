#include <linux/init.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

MODULE_LICENSE("GPL");

#define UMDP_GENL_NAME "UMDP"
#define UMDP_GENL_VERSION 1

/* attributes */
enum {
    UMDP_ATTR_UNSPEC = 0,
    UMDP_ATTR_MSG = 1,
    __UMDP_ATTR_MAX,
};
#define UMDP_ATTR_MAX (__UMDP_ATTR_MAX - 1)

/* attribute policy */
static struct nla_policy umdp_genl_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_MSG] = {
        .type = NLA_NUL_STRING,
    },
};

/* commands */
enum {
    UMDP_CMD_UNSPEC = 0,
    UMDP_CMD_ECHO = 1,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

static int umdp_echo(struct sk_buff* skb, struct genl_info* info);

/* operation definition */
static const struct genl_ops umdp_genl_ops[] = {
    {
        .cmd = UMDP_CMD_ECHO,
        .flags = 0,
        .policy = umdp_genl_policy,
        .doit = umdp_echo,
        .dumpit = NULL
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
    int msglen = genlmsg_len(info->genlhdr);
    char* msg = genlmsg_data(info->genlhdr);

    struct sk_buff* reply = genlmsg_new(NLMSG_HDRLEN + GENL_HDRLEN + msglen, GFP_KERNEL);
    if (reply == NULL) {
        printk(KERN_ALERT "[umdp] Failed to allocate buffer for response\n");
        return -ENOMEM;
    }

    void* reply_header = genlmsg_put_reply(reply, info, &umdp_genl_family, 0, UMDP_CMD_ECHO);
    if (reply_header == NULL) {
        nlmsg_free(reply);
        printk(KERN_ALERT "[umdp] \n"); // TODO
        return -EINVAL;  // why EINVAL?
    }

    int ret = nla_put_string(reply, UMDP_ATTR_MSG, msg);
    if (ret != 0) {
        // TODO FAILURE
        printk(KERN_ALERT "[umdp] failed to put string\n"); // TODO
        return -1;
    }

    genlmsg_end(reply, reply_header);
    ret = genlmsg_reply(reply, info);
    if (ret != 0) {
        // TODO FAILURE
        printk(KERN_ALERT "[umdp] failed to send reply\n"); // TODO
        return -1;
    }

    return 0;
}

static int umdp_init(void) {
    printk(KERN_ALERT "Hello, world\n");

    int ret = genl_register_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ALERT "Failed to register netlink family\n");
        return 1;
    }

    printk(KERN_ALERT "Registered netlink kernel family\n");
    return 0;
}

static void umdp_exit(void) {
    int ret = genl_unregister_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ALERT "Failed to unregister netlink family\n");
    }

    printk(KERN_ALERT "Unregistered netlink family\n");
    printk(KERN_ALERT "Goodbye, cruel world\n");
}

module_init(umdp_init);
module_exit(umdp_exit);
