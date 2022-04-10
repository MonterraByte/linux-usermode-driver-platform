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

/* commands */
enum {
    UMDP_CMD_UNSPEC = 0,
    UMDP_CMD_ECHO = 1,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

/* attribute policy */
static struct nla_policy umdp_genl_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_MSG] = {
        .type = NLA_NUL_STRING,
    },
};

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
    printk(KERN_ALERT "umdp_echo handler start\n");
    umdp_dump(info);

    /*struct nlattr* attributes[UMDP_ATTR_MAX + 1];
    if (genlmsg_parse(info->nlhdr, &umdp_genl_family, attributes, UMDP_ATTR_MAX, umdp_genl_policy, NULL) != 0) {
        printk(KERN_ALERT "[umdp] failed to parse attributes\n"); // TODO
        return -1;
    }*/

    printk(KERN_ALERT "info->nlhdr: %p\n", info->nlhdr);
    printk(KERN_ALERT "info->genlhdr: %p\n", info->genlhdr);
    printk(KERN_ALERT "info->attrs: %p\n", info->attrs);

    struct nlattr** attributes = info->attrs;
    struct nlattr* msg_attr = NULL;

    int i;
    for (i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        if (attributes[i] == NULL) {
            printk(KERN_ALERT "Attribute %d was null\n", i);
            continue;
        }

        printk(KERN_ALERT "attributes[%d]: %p\n", i, attributes[i]);

        printk(KERN_ALERT "Attribute %d has type %d and length %d\n", i, attributes[i]->nla_type, attributes[i]->nla_len);
        if (attributes[i]->nla_type == UMDP_ATTR_MSG) {
            printk(KERN_ALERT "Found message attribute\n");
            msg_attr = attributes[i];
            break;
        }
    }

    if (msg_attr == NULL) {
        printk(KERN_ALERT "Did not find message attribute\n");
        return -1;
    }

    char* message_start = nla_data(msg_attr); //(char*) (msg_attr + (size_t) NLA_HDRLEN);
    int message_length = msg_attr->nla_len - NLA_HDRLEN;

    printk(KERN_ALERT "message_start: %p\n", message_start);
    printk(KERN_ALERT "message_length: %d\n", message_length);
    printk(KERN_ALERT "nla_len: %d\n", nla_len(msg_attr));

    for (i = 0; i < message_length; i++) {
        printk(KERN_ALERT "message_start[%d]: %c\n", i, message_start[i]);
    }

    printk(KERN_ALERT "It said: %s\n", message_start);

    struct sk_buff* reply = genlmsg_new(NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(message_length), GFP_KERNEL);
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

    int ret = nla_put_string(reply, UMDP_ATTR_MSG, message_start);
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
    printk(KERN_ALERT "Hello, world\n\n");
    printk(KERN_ALERT "sizeof(struct nlmsghdr): %lu\n", sizeof(struct nlmsghdr));
    printk(KERN_ALERT "NLMSG_HDRLEN: %d\n\n", NLMSG_HDRLEN);
    printk(KERN_ALERT "sizeof(struct genlmsghdr): %lu\n", sizeof(struct genlmsghdr));
    printk(KERN_ALERT "GENL_HDRLEN: %lu\n\n", GENL_HDRLEN);
    printk(KERN_ALERT "sizeof(struct nlattr): %lu\n", sizeof(struct nlattr));
    printk(KERN_ALERT "NLA_HDRLEN: %d\n\n", NLA_HDRLEN);


    int ret = genl_register_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ALERT "Failed to register netlink family\n");
        return 1;
    }

    printk(KERN_ALERT "Registered netlink kernel family (id: %d)\n", umdp_genl_family.id);
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
