#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/mutex.h>
//#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <net/netlink.h>

MODULE_DESCRIPTION("User mode driver platform");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joaquim Monteiro <joaquim.monteiro@protonmail.com>");

#define UMDP_GENL_NAME "UMDP"
#define UMDP_GENL_VERSION 1
#define UMDP_GENL_INTERRUPT_MULTICAST_NAME "interrupt"

#define UMDP_DEVICE_NAME "umdp"
#define UMDP_MAX_PORT_ALLOCATIONS 16
#define UMDP_MAX_IRQ_SUBSCRIPTIONS 16
#define UMDP_WORKQUEUE_NAME "umdp_wq"
#define UMDP_WORKER_COUNT 32

/* attributes */
enum {
    UMDP_ATTR_UNSPEC __attribute__((unused)) = 0,
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
    UMDP_CMD_UNSPEC __attribute__((unused)) = 0,
    UMDP_CMD_ECHO = 1,
    UMDP_CMD_DEVIO_READ = 2,
    UMDP_CMD_DEVIO_WRITE = 3,
    UMDP_CMD_DEVIO_REQUEST = 4,
    UMDP_CMD_DEVIO_RELEASE = 5,
    UMDP_CMD_INTERRUPT_NOTIFICATION = 6,
    UMDP_CMD_INTERRUPT_SUBSCRIBE = 7,
    UMDP_CMD_INTERRUPT_UNSUBSCRIBE = 8,
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

static struct nla_policy umdp_genl_interrupt_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_U32] =
        {
            .type = NLA_U32,
        },
};

static int umdp_echo(struct sk_buff* skb, struct genl_info* info);
static int umdp_devio_read(struct sk_buff* skb, struct genl_info* info);
static int umdp_devio_write(struct sk_buff* skb, struct genl_info* info);
static int umdp_devio_request(struct sk_buff* skb, struct genl_info* info);
static int umdp_devio_release(struct sk_buff* skb, struct genl_info* info);
static int umdp_interrupt_subscribe(struct sk_buff* skb, struct genl_info* info);
static int umdp_interrupt_unsubscribe(struct sk_buff* skb, struct genl_info* info);
static int umdp_interrupt_notification(struct sk_buff* skb, struct genl_info* info) { return 0; }

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
        .flags = 0,  // TODO: maybe GENL_ADMIN_PERM?
        .policy = umdp_genl_devio_policy,
        .doit = umdp_devio_read,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_WRITE,
        .flags = 0,  // TODO: maybe GENL_ADMIN_PERM?
        .policy = umdp_genl_devio_policy,
        .doit = umdp_devio_write,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_REQUEST,
        .flags = 0,
        .policy = umdp_genl_devio_policy,
        .doit = umdp_devio_request,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_RELEASE,
        .flags = 0,
        .policy = umdp_genl_devio_policy,
        .doit = umdp_devio_release,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_INTERRUPT_NOTIFICATION,
        .flags = 0,
        .policy = umdp_genl_interrupt_policy,
        //.doit = NULL,
        .doit = umdp_interrupt_notification,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_INTERRUPT_SUBSCRIBE,
        .flags = 0,
        .policy = umdp_genl_interrupt_policy,
        .doit = umdp_interrupt_subscribe,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_INTERRUPT_UNSUBSCRIBE,
        .flags = 0,
        .policy = umdp_genl_interrupt_policy,
        .doit = umdp_interrupt_unsubscribe,
        .dumpit = NULL,
    },

};

static const struct genl_multicast_group umdp_genl_multicast_groups[] = {
    {
        .name = UMDP_GENL_INTERRUPT_MULTICAST_NAME,
    },
};

/* family definition */
static struct genl_family umdp_genl_family = {
    .name = UMDP_GENL_NAME,
    .version = UMDP_GENL_VERSION,
    .maxattr = UMDP_ATTR_MAX,
    .ops = umdp_genl_ops,
    .n_ops = ARRAY_SIZE(umdp_genl_ops),
    .mcgrps = umdp_genl_multicast_groups,
    .n_mcgrps = ARRAY_SIZE(umdp_genl_multicast_groups),
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

struct devio_data {
    u64 allocated_ports[UMDP_MAX_PORT_ALLOCATIONS];
    size_t allocated_port_count;
};
static struct devio_data devio_data;
DEFINE_MUTEX(devio_data_mutex);

static size_t umdp_devio_find_allocated_port_index(u64 port) {
    size_t i;
    for (i = 0; i < devio_data.allocated_port_count; i++) {
        if (devio_data.allocated_ports[i] == port) {
            return i;
        }
    }
    return SIZE_MAX;
}

static int umdp_devio_read(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received device IO read request\n");

    struct nlattr* port_attr = find_attribute(info->attrs, UMDP_ATTR_U64);
    if (port_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO read request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *(u64*) nla_data(port_attr);

    mutex_lock(&devio_data_mutex);

    size_t port_index = umdp_devio_find_allocated_port_index(port);
    if (port_index == SIZE_MAX) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: port %llu isn't registered, so it can't be read from\n", port);
        return -EPERM;
    }

    mutex_unlock(&devio_data_mutex);

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

    mutex_lock(&devio_data_mutex);

    size_t port_index = umdp_devio_find_allocated_port_index(port);
    if (port_index == SIZE_MAX) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: port %llu isn't registered, so it can't be written to\n", port);
        return -EPERM;
    }

    mutex_unlock(&devio_data_mutex);

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

static int umdp_devio_request(struct sk_buff* skb, struct genl_info* info) {
    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_U64);
    if (irq_attr == NULL) {
        printk(KERN_ERR "umdp: invalid IO port subscription request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *((u64*) nla_data(irq_attr));

    mutex_lock(&devio_data_mutex);

    if (umdp_devio_find_allocated_port_index(port) != SIZE_MAX) {
        // already allocated
        mutex_unlock(&devio_data_mutex);
        return 0;
    }

    if (devio_data.allocated_port_count == UMDP_MAX_PORT_ALLOCATIONS) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: reached port allocation limit, cannot register another one\n");
        return -EBUSY;
    }

    if (request_region(port, 1, UMDP_DEVICE_NAME) == NULL) {
        // TODO: if needed "release" the port
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: failed to request port %llu, it's currently unavailable\n", port);
        return -EBUSY;
    }

    devio_data.allocated_port_count++;
    devio_data.allocated_ports[devio_data.allocated_port_count - 1] = port;

    mutex_unlock(&devio_data_mutex);
    return 0;
}

static int umdp_devio_release(struct sk_buff* skb, struct genl_info* info) {
    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_U64);
    if (irq_attr == NULL) {
        printk(KERN_ERR "umdp: invalid IO port release request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *((u64*) nla_data(irq_attr));

    mutex_lock(&devio_data_mutex);

    size_t port_index = umdp_devio_find_allocated_port_index(port);
    if (port_index == SIZE_MAX) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: port %llu isn't registered, so it cannot be unregistered\n", port);
        return -ENOENT;
    }

    devio_data.allocated_port_count--;
    size_t i;
    for (i = port_index; i < devio_data.allocated_port_count; i++) {
        devio_data.allocated_ports[i] = devio_data.allocated_ports[i+1];
    }

    release_region(port, 1);
    mutex_unlock(&devio_data_mutex);
    return 0;
}

struct ih_data {
    u32 registered_irqs[UMDP_MAX_IRQ_SUBSCRIPTIONS];
    size_t registered_irq_count;

    u64 interrupt_count;
    u64 handled_interrupt_count;
};
static struct ih_data ih_data;
DEFINE_MUTEX(ih_data_mutex);

static struct workqueue_struct* ih_workqueue;
void interrupt_handler_wq(struct work_struct* ws);

struct ih_work_struct {
    struct work_struct ws;
    int irq;
    bool busy;
};
static struct ih_work_struct ih_workers[UMDP_WORKER_COUNT];

static irqreturn_t interrupt_handler(int irq, void *dev_id) {
    ih_data.interrupt_count++;
    size_t i;
    for (i = 0; i < UMDP_WORKER_COUNT; i++) {
        if (!ih_workers[i].busy) {
            ih_workers[i].busy = true;
            ih_workers[i].irq = irq;
            INIT_WORK(&ih_workers[i].ws, interrupt_handler_wq);
            queue_work(ih_workqueue, (struct work_struct*) &ih_workers[i]);

            ih_data.handled_interrupt_count++;
            break;
        }
    }
    return IRQ_HANDLED;
}

void interrupt_handler_wq(struct work_struct* ws) {
    struct ih_work_struct* work = (struct ih_work_struct*) ws;

    struct sk_buff* msg = genlmsg_new(nla_total_size(sizeof(u32)), GFP_KERNEL);
    if (msg == NULL) {
        printk(KERN_ERR "umdp: failed to allocate buffer for interrupt notification\n");
        work->busy = false;
        return;
    }

    void* msg_header = genlmsg_put(msg, 0, 0, &umdp_genl_family, 0, UMDP_CMD_INTERRUPT_NOTIFICATION);
    if (msg_header == NULL) {
        nlmsg_free(msg);
        printk(KERN_ERR "umdp: failed to add the generic netlink header to the interrupt notification\n");
        work->busy = false;
        return;
    }

    if (nla_put_u32(msg, UMDP_ATTR_U32, work->irq) != 0) {
        nlmsg_free(msg);
        printk(KERN_ERR "umdp: failed to write value to interrupt notification (this is a bug)\n");
        work->busy = false;
        return;
    }

    genlmsg_end(msg, msg_header);
    int ret = genlmsg_multicast(&umdp_genl_family, msg, 0, 0, GFP_KERNEL);
    if (ret == -ESRCH) {
        printk(KERN_DEBUG "umdp: tried to send notification for IRQ %d, but no one is listening\n", work->irq);
        work->busy = false;
        return;
    } else if (ret != 0) {
        printk(KERN_ERR "umdp: failed to send interrupt notification (error code %d)\n", ret);
        work->busy = false;
        return;
    }

    printk(KERN_DEBUG "umdp: sent interrupt notification for IRQ %u\n", work->irq);
    work->busy = false;
}

static int umdp_interrupt_subscribe(struct sk_buff* skb, struct genl_info* info) {
    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_U32);
    if (irq_attr == NULL) {
        printk(KERN_ERR "umdp: invalid interrupt subscription request: IRQ attribute is missing\n");
        return -EINVAL;
    }
    u32 irq = *((u32*) nla_data(irq_attr));

    mutex_lock(&ih_data_mutex);

    size_t i;
    for (i = 0; i < ih_data.registered_irq_count; i++) {
        if (ih_data.registered_irqs[i] == irq) {
            mutex_unlock(&ih_data_mutex);
            return 0;
        }
    }

    if (ih_data.registered_irq_count == UMDP_MAX_IRQ_SUBSCRIPTIONS) {
        mutex_unlock(&ih_data_mutex);
        printk(KERN_ERR "umdp: reached interrupt subscription limit, cannot register another one\n");
        return -EBUSY;
    }

    // TODO: allow the user to decide if they want IRQF_SHARED
    int ret = request_irq(irq, interrupt_handler, IRQF_SHARED, UMDP_DEVICE_NAME, &ih_data);
    if (ret != 0) {
        mutex_unlock(&ih_data_mutex);
        printk(KERN_ERR "umdp: IRQ request failed with code %d\n", ret);
        return ret;
    }

    ih_data.registered_irq_count++;
    ih_data.registered_irqs[ih_data.registered_irq_count - 1] = irq;

    mutex_unlock(&ih_data_mutex);
    printk(KERN_INFO "umdp: subscribed to IRQ %u\n", irq);
    printk(KERN_INFO "umdp: client port id: %u\n", info->snd_portid);
    return 0;
}

static int umdp_interrupt_unsubscribe(struct sk_buff* skb, struct genl_info* info) {
    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_U32);
    if (irq_attr == NULL) {
        printk(KERN_ERR "umdp: invalid interrupt subscription request: IRQ attribute is missing\n");
        return -EINVAL;
    }
    u32 irq = *((u32*) nla_data(irq_attr));

    mutex_lock(&ih_data_mutex);

    size_t irq_index = SIZE_MAX;
    size_t i;
    for (i = 0; i < ih_data.registered_irq_count; i++) {
        if (ih_data.registered_irqs[i] == irq) {
            irq_index = i;
            break;
        }
    }

    if (irq_index == SIZE_MAX) {
        mutex_unlock(&ih_data_mutex);
        printk(KERN_ERR "umdp: IRQ %u isn't registered, so it cannot be unregistered\n", irq);
        return -ENOENT;
    }

    ih_data.registered_irq_count--;
    for (i = irq_index; i < ih_data.registered_irq_count; i++) {
        ih_data.registered_irqs[i] = ih_data.registered_irqs[i+1];
    }

    free_irq(irq, &ih_data);
    mutex_unlock(&ih_data_mutex);
    printk(KERN_INFO "umdp: unsubscribed from IRQ %u\n", irq);
    return 0;
}

//void ih_timer_callback(struct timer_list* timer) {
//    size_t i;
//    for (i = 0; i < UMDP_WORKER_COUNT; i++) {
//        if (!ih_workers[i].busy) {
//            ih_workers[i].busy = true;
//            ih_workers[i].irq = 0;
//            INIT_WORK(&ih_workers[i].ws, interrupt_handler_wq);
//            queue_work(ih_workqueue, (struct work_struct*) &ih_workers[i]);
//            break;
//        }
//    }
//    mod_timer(timer, jiffies + msecs_to_jiffies(5000));
//}

//static struct timer_list ih_timer;

static int umdp_init(void) {
    devio_data.allocated_port_count = 0;
    ih_data.registered_irq_count = 0;
    ih_data.interrupt_count = 0;
    ih_data.handled_interrupt_count = 0;

    ih_workqueue = alloc_workqueue(UMDP_WORKQUEUE_NAME, 0, 0);
    size_t i;
    for (i = 0; i < UMDP_WORKER_COUNT; i++) {
        ih_workers[i].busy = false;
    }

    int ret = genl_register_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to register netlink family (error code %d)\n", ret);
        return ret;
    }

    //timer_setup(&ih_timer, ih_timer_callback, 0);
    //mod_timer(&ih_timer, jiffies + msecs_to_jiffies(5000));

    printk(KERN_INFO "umdp: Registered netlink kernel family (id: %d)\n", umdp_genl_family.id);
    return 0;
}

static void umdp_exit(void) {
    int ret = genl_unregister_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to unregister netlink family\n");
    } else {
        printk(KERN_INFO "umdp: Unregistered netlink family\n");
    }

    //del_timer_sync(&ih_timer);
    destroy_workqueue(ih_workqueue);

    mutex_lock(&ih_data_mutex);

    size_t i;
    for (i = 0; i < ih_data.registered_irq_count; i++) {
        free_irq(ih_data.registered_irqs[i], &ih_data);
    }

    mutex_unlock(&ih_data_mutex);

    mutex_lock(&devio_data_mutex);

    //size_t i;
    for (i = 0; i < devio_data.allocated_port_count; i++) {
        release_region(devio_data.allocated_ports[i], 1);
    }

    mutex_unlock(&devio_data_mutex);

    printk(KERN_INFO "umdp: received a total of %llu interrupts\n", ih_data.interrupt_count);
    printk(KERN_INFO "umdp: handled a total of %llu interrupts\n", ih_data.handled_interrupt_count);
}

module_init(umdp_init);
module_exit(umdp_exit);
