#include <linux/cdev.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/sock.h>

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

/* commands */
enum {
    UMDP_CMD_UNSPEC __attribute__((unused)) = 0,
    UMDP_CMD_ECHO = 1,
    UMDP_CMD_CONNECT = 2,
    UMDP_CMD_DEVIO_READ = 3,
    UMDP_CMD_DEVIO_WRITE = 4,
    UMDP_CMD_DEVIO_REQUEST = 5,
    UMDP_CMD_DEVIO_RELEASE = 6,
    UMDP_CMD_INTERRUPT_NOTIFICATION = 7,
    UMDP_CMD_INTERRUPT_SUBSCRIBE = 8,
    UMDP_CMD_INTERRUPT_UNSUBSCRIBE = 9,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

// Should be updated as needed when attributes are added/removed.
// The `static_assert`s make sure the value it at least correct.
#define UMDP_ATTR_MAX 5

// echo attributes
enum {
    UMDP_ATTR_ECHO_UNSPEC __attribute__((unused)) = 0,
    UMDP_ATTR_ECHO_MSG = 1,
    __UMDP_ATTR_ECHO_MAX,
};
#define UMDP_ATTR_ECHO_MAX (__UMDP_ATTR_ECHO_MAX - 1)
static_assert(UMDP_ATTR_ECHO_MAX <= UMDP_ATTR_MAX);

static struct nla_policy umdp_genl_echo_policy[UMDP_ATTR_ECHO_MAX + 1] = {
    [UMDP_ATTR_ECHO_MSG] =
        {
            .type = NLA_NUL_STRING,
        },
};

// connect attributes
enum {
    UMDP_ATTR_CONNECT_UNSPEC __attribute__((unused)) = 0,
    UMDP_ATTR_CONNECT_PID = 1,
    UMDP_ATTR_CONNECT_REPLY = 2,
    __UMDP_ATTR_CONNECT_MAX,
};
#define UMDP_ATTR_CONNECT_MAX (__UMDP_ATTR_CONNECT_MAX - 1)
static_assert(UMDP_ATTR_CONNECT_MAX <= UMDP_ATTR_MAX);

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
static_assert(sizeof(pid_t) == sizeof(s32));

// devio read attributes
enum {
    UMDP_ATTR_DEVIO_READ_UNSPEC __attribute__((unused)) = 0,
    UMDP_ATTR_DEVIO_READ_PORT = 1,
    UMDP_ATTR_DEVIO_READ_TYPE = 2,
    UMDP_ATTR_DEVIO_READ_REPLY_U8 = 3,
    UMDP_ATTR_DEVIO_READ_REPLY_U16 = 4,
    UMDP_ATTR_DEVIO_READ_REPLY_U32 = 5,
    __UMDP_ATTR_DEVIO_READ_MAX,
};
#define UMDP_ATTR_DEVIO_READ_MAX (__UMDP_ATTR_DEVIO_READ_MAX - 1)
static_assert(UMDP_ATTR_DEVIO_READ_MAX <= UMDP_ATTR_MAX);

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

// devio write attributes
enum {
    UMDP_ATTR_DEVIO_WRITE_UNSPEC __attribute__((unused)) = 0,
    UMDP_ATTR_DEVIO_WRITE_PORT = 1,
    UMDP_ATTR_DEVIO_WRITE_VALUE_U8 = 2,
    UMDP_ATTR_DEVIO_WRITE_VALUE_U16 = 3,
    UMDP_ATTR_DEVIO_WRITE_VALUE_U32 = 4,
    __UMDP_ATTR_DEVIO_WRITE_MAX,
};
#define UMDP_ATTR_DEVIO_WRITE_MAX (__UMDP_ATTR_DEVIO_WRITE_MAX - 1)
static_assert(UMDP_ATTR_DEVIO_WRITE_MAX <= UMDP_ATTR_MAX);

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

// devio request attributes
enum {
    UMDP_ATTR_DEVIO_REQUEST_UNSPEC __attribute__((unused)) = 0,
    UMDP_ATTR_DEVIO_REQUEST_START = 1,
    UMDP_ATTR_DEVIO_REQUEST_SIZE = 2,
    __UMDP_ATTR_DEVIO_REQUEST_MAX,
};
#define UMDP_ATTR_DEVIO_REQUEST_MAX (__UMDP_ATTR_DEVIO_REQUEST_MAX - 1)
static_assert(UMDP_ATTR_DEVIO_REQUEST_MAX <= UMDP_ATTR_MAX);

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

// interrupt attributes
enum {
    UMDP_ATTR_INTERRUPT_UNSPEC __attribute__((unused)) = 0,
    UMDP_ATTR_INTERRUPT_IRQ = 1,
    __UMDP_ATTR_INTERRUPT_MAX,
};
#define UMDP_ATTR_INTERRUPT_MAX (__UMDP_ATTR_INTERRUPT_MAX - 1)
static_assert(UMDP_ATTR_INTERRUPT_MAX <= UMDP_ATTR_MAX);

static struct nla_policy umdp_genl_interrupt_policy[UMDP_ATTR_INTERRUPT_MAX + 1] = {
    [UMDP_ATTR_INTERRUPT_IRQ] =
        {
            .type = NLA_U32,
        },
};

static int umdp_echo(struct sk_buff* skb, struct genl_info* info);
static int umdp_connect(struct sk_buff* skb, struct genl_info* info);
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
        .maxattr = UMDP_ATTR_ECHO_MAX,
        .policy = umdp_genl_echo_policy,
        .doit = umdp_echo,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_CONNECT,
        .flags = 0,
        .maxattr = UMDP_ATTR_CONNECT_MAX,
        .policy = umdp_genl_connect_policy,
        .doit = umdp_connect,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_READ,
        .flags = 0,
        .maxattr = UMDP_ATTR_DEVIO_READ_MAX,
        .policy = umdp_genl_devio_read_policy,
        .doit = umdp_devio_read,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_WRITE,
        .flags = 0,
        .maxattr = UMDP_ATTR_DEVIO_WRITE_MAX,
        .policy = umdp_genl_devio_write_policy,
        .doit = umdp_devio_write,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_REQUEST,
        .flags = 0,
        .maxattr = UMDP_ATTR_DEVIO_REQUEST_MAX,
        .policy = umdp_genl_devio_request_policy,
        .doit = umdp_devio_request,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_DEVIO_RELEASE,
        .flags = 0,
        .maxattr = UMDP_ATTR_DEVIO_REQUEST_MAX,
        .policy = umdp_genl_devio_request_policy,
        .doit = umdp_devio_release,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_INTERRUPT_NOTIFICATION,
        .flags = 0,
        .maxattr = UMDP_ATTR_INTERRUPT_MAX,
        .policy = umdp_genl_interrupt_policy,
        .doit = umdp_interrupt_notification,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_INTERRUPT_SUBSCRIBE,
        .flags = 0,
        .maxattr = UMDP_ATTR_INTERRUPT_MAX,
        .policy = umdp_genl_interrupt_policy,
        .doit = umdp_interrupt_subscribe,
        .dumpit = NULL,
    },
    {
        .cmd = UMDP_CMD_INTERRUPT_UNSUBSCRIBE,
        .flags = 0,
        .maxattr = UMDP_ATTR_INTERRUPT_MAX,
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
    struct nlattr* type_attr = attributes[type];
    if (type_attr != NULL && nla_type(type_attr) == type) {
        return type_attr;
    }
    return NULL;
}

/* UMDP_CMD_ECHO handler */
static int umdp_echo(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received echo request\n");

    struct nlattr* msg_attr = find_attribute(info->attrs, UMDP_ATTR_ECHO_MSG);
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

    int ret = nla_put_string(reply, UMDP_ATTR_ECHO_MSG, nla_data(msg_attr));
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

struct client_info {
    struct list_head list;
    u32 port_id;
    struct pid* pid;
};
static LIST_HEAD(client_info_list);
static DECLARE_RWSEM(client_info_lock);
#define for_each_client_info(p) list_for_each_entry(p, &client_info_list, list)
#define for_each_client_info_safe(p, next) list_for_each_entry_safe(p, next, &client_info_list, list)

// client_info_list write lock must be acquired when calling this
static bool register_client(u32 port_id, struct pid* pid) {
    struct client_info* client_info = kmalloc(sizeof(struct client_info), GFP_KERNEL);
    if (client_info == NULL) {
        printk(KERN_ERR "umdp: failed to allocate memory for client info\n");
        return false;
    }

    INIT_LIST_HEAD(&client_info->list);
    client_info->port_id = port_id;
    client_info->pid = pid;

    list_add_tail(&client_info->list, &client_info_list);
    return true;
}

// client_info_list write lock must be acquired when calling this
static bool register_client_if_not_registered(u32 port_id, struct pid* pid) {
    struct client_info* p;
    for_each_client_info(p) {
        if (p->port_id == port_id) {
            // already registered
            printk(KERN_ERR "umdp: port ID %d was already registered, it cannot be registered again\n", port_id);
            return false;
        }
    }

    return register_client(port_id, pid);
}

// `struct netlink_sock` is defined in `net/netlink/af_netlink.h` in the kernel source code, which isn't part of the "public" headers.
// However, we need to access the portid.
// The following is an evil hack, pray that the alignment matches the original struct.

struct partial_netlink_sock {
    struct sock sk __attribute__((unused));
    unsigned long flags __attribute__((unused));
    u32 portid;
    // ...
};

static int check_if_open_file_is_netlink_socket_with_port_id(
    const void* v, struct file* file, __attribute__((unused)) unsigned fd) {
    struct socket* socket = sock_from_file(file);
    if (socket == NULL || socket->ops->family != PF_NETLINK) {
        return 0;
    }

    struct partial_netlink_sock* nlk = container_of(socket->sk, struct partial_netlink_sock, sk);
    printk(KERN_DEBUG "umdp: found netlink socket with portid %u:\n", nlk->portid);

    u32 expected_port_id = *(u32*) v;
    if (nlk->portid == expected_port_id) {
        // Returning a non-zero value causes `iterate_fd` to return early.
        return 1;
    }

    return 0;
}

static bool check_process_for_netlink_socket_with_port_id(struct pid* pid, u32 port_id) {
    struct task_struct* task = get_pid_task(pid, PIDTYPE_PID);
    if (task == NULL) {
        return false;
    }
    int result = iterate_fd(task->files, 0, check_if_open_file_is_netlink_socket_with_port_id, &port_id);
    put_task_struct(task);

    return result != 0;
}

static int umdp_connect(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received connect request from portid %u\n", info->snd_portid);

    struct nlattr* pid_attr = find_attribute(info->attrs, UMDP_ATTR_CONNECT_PID);
    if (pid_attr == NULL) {
        printk(KERN_ERR "umdp: did not find PID attribute in echo request\n");
        return -EINVAL;
    }
    s32 pid_number = *(s32*) nla_data(pid_attr);

    struct pid* pid = find_get_pid(pid_number);
    bool found = check_process_for_netlink_socket_with_port_id(pid, info->snd_portid);

    bool registered = false;
    if (found) {
        printk(KERN_DEBUG "umdp: connect request was from pid %d\n", pid_number);
        down_write(&client_info_lock);
        registered = register_client_if_not_registered(info->snd_portid, pid);
        up_write(&client_info_lock);
    }

    if (!registered) {
        put_pid(pid);
    }

    struct sk_buff* reply = genlmsg_new(nla_total_size(sizeof(u8)), GFP_KERNEL);
    if (reply == NULL) {
        printk(KERN_ERR "umdp: failed to allocate buffer for connect reply\n");
        return -ENOMEM;
    }

    void* reply_header = genlmsg_put_reply(reply, info, &umdp_genl_family, 0, UMDP_CMD_CONNECT);
    if (reply_header == NULL) {
        nlmsg_free(reply);
        printk(KERN_ERR "umdp: failed to add the generic netlink header to the connect reply\n");
        return -EMSGSIZE;
    }

    u8 value = registered ? 1 : 0;
    int ret = nla_put_u8(reply, UMDP_ATTR_CONNECT_REPLY, value);
    if (ret != 0) {
        nlmsg_free(reply);
        printk(KERN_ERR "umdp: failed to write value to reply\n");
        return ret;
    }

    genlmsg_end(reply, reply_header);
    ret = genlmsg_reply(reply, info);
    if (ret != 0) {
        printk(KERN_ERR "umdp: failed to send connect reply\n");
        return ret;
    }

    return 0;
}

struct devio_region {
    u64 start;
    u64 size;
};

struct devio_data {
    struct devio_region allocated_regions[UMDP_MAX_PORT_ALLOCATIONS];
    size_t allocated_region_count;
};
static struct devio_data devio_data;
DEFINE_MUTEX(devio_data_mutex);

static size_t find_allocated_region_index(struct devio_region* region) {
    size_t i;
    for (i = 0; i < devio_data.allocated_region_count; i++) {
        if (devio_data.allocated_regions[i].start == region->start
            && devio_data.allocated_regions[i].size == region->size) {
            return i;
        }
    }
    return SIZE_MAX;
}

static bool is_ioport_allocated(u64 port) {
    size_t i;
    for (i = 0; i < devio_data.allocated_region_count; i++) {
        u64 start = devio_data.allocated_regions[i].start;
        u64 size = devio_data.allocated_regions[i].size;
        if (start <= port && port < start + size) {
            return true;
        }
    }
    return false;
}

static int umdp_devio_read(struct sk_buff* skb, struct genl_info* info) {
    printk(KERN_DEBUG "umdp: received device IO read request\n");

    struct nlattr* port_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_READ_PORT);
    if (port_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO read request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *(u64*) nla_data(port_attr);

    mutex_lock(&devio_data_mutex);

    if (!is_ioport_allocated(port)) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: port %llu isn't registered, so it can't be read from\n", port);
        return -EPERM;
    }

    mutex_unlock(&devio_data_mutex);

    struct nlattr* type_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_READ_TYPE);
    if (type_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO read request: type attribute is missing\n");
        return -EINVAL;
    }

    int reply_size;
    switch (*(u8*) nla_data(type_attr)) {
        case UMDP_ATTR_DEVIO_READ_REPLY_U8:
            reply_size = sizeof(u8);
            break;
        case UMDP_ATTR_DEVIO_READ_REPLY_U16:
            reply_size = sizeof(u16);
            break;
        case UMDP_ATTR_DEVIO_READ_REPLY_U32:
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
            ret = nla_put_u8(reply, UMDP_ATTR_DEVIO_READ_REPLY_U8, value);
            break;
        }
        case sizeof(u16): {
            u16 value = inw(port);
            printk(KERN_DEBUG "umdp: read %u (%x) from port %llu\n", value, value, port);
            ret = nla_put_u16(reply, UMDP_ATTR_DEVIO_READ_REPLY_U16, value);
            break;
        }
        case sizeof(u32): {
            u32 value = inl(port);
            printk(KERN_DEBUG "umdp: read %u (%x) from port %llu\n", value, value, port);
            ret = nla_put_u32(reply, UMDP_ATTR_DEVIO_READ_REPLY_U32, value);
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

    struct nlattr* port_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_WRITE_PORT);
    if (port_attr == NULL) {
        printk(KERN_ERR "umdp: invalid device IO write request: port attribute is missing\n");
        return -EINVAL;
    }
    u64 port = *((u64*) nla_data(port_attr));

    mutex_lock(&devio_data_mutex);

    if (!is_ioport_allocated(port)) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: port %llu isn't registered, so it can't be written to\n", port);
        return -EPERM;
    }

    mutex_unlock(&devio_data_mutex);

    int i;
    for (i = 0; i < UMDP_ATTR_DEVIO_WRITE_MAX + 1; i++) {
        if (info->attrs[i] == NULL) {
            continue;
        }

        switch (nla_type(info->attrs[i])) {
            case UMDP_ATTR_DEVIO_WRITE_VALUE_U8: {
                u8 value = *((u8*) nla_data(info->attrs[i]));
                printk(KERN_DEBUG "umdp: writing %u (%x) to port %llu\n", value, value, port);
                outb(value, port);
                return 0;
            }
            case UMDP_ATTR_DEVIO_WRITE_VALUE_U16: {
                u16 value = *((u16*) nla_data(info->attrs[i]));
                printk(KERN_DEBUG "umdp: writing %u (%x) to port %llu\n", value, value, port);
                outw(value, port);
                return 0;
            }
            case UMDP_ATTR_DEVIO_WRITE_VALUE_U32: {
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
    struct nlattr* start_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_REQUEST_START);
    struct nlattr* size_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_REQUEST_SIZE);

    if (start_attr == NULL || size_attr == NULL) {
        printk(KERN_ERR "umdp: invalid IO region request\n");
        return -EINVAL;
    }
    struct devio_region region = {
        .start = *((u64*) nla_data(start_attr)),
        .size = *((u64*) nla_data(size_attr)),
    };
    printk(KERN_DEBUG "umdp: received request for region %llu - %llu\n", region.start, region.start + region.size - 1);
    if (region.size == 0) {
        printk(KERN_ERR "umdp: I/O regions cannot have size 0\n");
        return -EINVAL;
    }

    mutex_lock(&devio_data_mutex);

    if (find_allocated_region_index(&region) != SIZE_MAX) {
        // already allocated
        mutex_unlock(&devio_data_mutex);
        return 0;
    }

    if (devio_data.allocated_region_count == UMDP_MAX_PORT_ALLOCATIONS) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: reached port allocation limit, cannot register another one\n");
        return -EBUSY;
    }

    if (request_region(region.start, region.size, UMDP_DEVICE_NAME) == NULL) {
        release_region(region.start, region.size);
        if (request_region(region.start, region.size, UMDP_DEVICE_NAME) == NULL) {
            mutex_unlock(&devio_data_mutex);
            printk(KERN_ERR "umdp: failed to request region %llu - %llu, it's currently unavailable\n", region.start,
                region.start + region.size - 1);
            return -EBUSY;
        }
    }

    devio_data.allocated_region_count++;
    devio_data.allocated_regions[devio_data.allocated_region_count - 1] = region;

    mutex_unlock(&devio_data_mutex);
    printk(
        KERN_DEBUG "umdp: region %llu - %llu allocated successfully\n", region.start, region.start + region.size - 1);
    return 0;
}

static int umdp_devio_release(struct sk_buff* skb, struct genl_info* info) {
    struct nlattr* start_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_REQUEST_START);
    struct nlattr* size_attr = find_attribute(info->attrs, UMDP_ATTR_DEVIO_REQUEST_SIZE);

    if (start_attr == NULL || size_attr == NULL) {
        printk(KERN_ERR "umdp: invalid IO region release request\n");
        return -EINVAL;
    }
    struct devio_region region = {
        .start = *((u64*) nla_data(start_attr)),
        .size = *((u64*) nla_data(size_attr)),
    };
    printk(KERN_DEBUG "umdp: received release request for region %llu - %llu\n", region.start,
        region.start + region.size - 1);

    mutex_lock(&devio_data_mutex);

    size_t port_index = find_allocated_region_index(&region);
    if (port_index == SIZE_MAX) {
        mutex_unlock(&devio_data_mutex);
        printk(KERN_ERR "umdp: region %llu - %llu isn't allocated, so it cannot be released\n", region.start,
            region.start + region.size - 1);
        return -ENOENT;
    }

    devio_data.allocated_region_count--;
    size_t i;
    for (i = port_index; i < devio_data.allocated_region_count; i++) {
        devio_data.allocated_regions[i] = devio_data.allocated_regions[i + 1];
    }

    release_region(region.start, region.size);
    mutex_unlock(&devio_data_mutex);
    printk(KERN_DEBUG "umdp: region %llu - %llu released successfully\n", region.start, region.start + region.size - 1);
    return 0;
}

struct ih_data {
    u32 registered_irqs[UMDP_MAX_IRQ_SUBSCRIPTIONS];
    size_t registered_irq_count;
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

static irqreturn_t interrupt_handler(int irq, void* dev_id) {
    size_t i;
    for (i = 0; i < UMDP_WORKER_COUNT; i++) {
        if (!ih_workers[i].busy) {
            ih_workers[i].busy = true;
            ih_workers[i].irq = irq;
            INIT_WORK(&ih_workers[i].ws, interrupt_handler_wq);
            queue_work(ih_workqueue, (struct work_struct*) &ih_workers[i]);
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

    if (nla_put_u32(msg, UMDP_ATTR_INTERRUPT_IRQ, work->irq) != 0) {
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
    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_INTERRUPT_IRQ);
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
    unsigned long flags = IRQF_SHARED;
    if (irq == 0) {
        flags |= IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER;
    }

    int ret = request_irq(irq, interrupt_handler, flags, UMDP_DEVICE_NAME, &ih_data);
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
    struct nlattr* irq_attr = find_attribute(info->attrs, UMDP_ATTR_INTERRUPT_IRQ);
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
        ih_data.registered_irqs[i] = ih_data.registered_irqs[i + 1];
    }

    free_irq(irq, &ih_data);
    mutex_unlock(&ih_data_mutex);
    printk(KERN_INFO "umdp: unsubscribed from IRQ %u\n", irq);
    return 0;
}

static int umdp_mem_open(struct inode* inode __attribute__((unused)), struct file* filep __attribute__((unused))) {
    return 0;
}

static int umdp_mem_release(struct inode* inode __attribute__((unused)), struct file* filep __attribute__((unused))) {
    return 0;
}

static int umdp_mem_mmap(struct file* file __attribute__((unused)), struct vm_area_struct* vma) {
    bool is_write = (vma->vm_flags & VM_WRITE) != 0;
    vm_flags_t shared_flags =
        VM_MAYSHARE | (is_write ? VM_SHARED : 0);  // is VM_MAYSHARE always set if VM_SHARED is set?
    if ((vma->vm_flags & shared_flags) != shared_flags) {
        printk(KERN_ERR "umdp: mmap requests must set the MAP_SHARED flag\n");
        return -EINVAL;
    }

    vma->__vm_flags |= VM_IO;

    printk(KERN_DEBUG "umdp: performing mmap of region 0x%lx-0x%lx to address 0x%lu of PID %d\n",
        vma->vm_pgoff * PAGE_SIZE, vma->vm_pgoff * PAGE_SIZE + (vma->vm_end - vma->vm_start), vma->vm_start,
        current->pid);
    return io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static struct file_operations umdp_mem_fops = {
    .owner = THIS_MODULE,
    .open = umdp_mem_open,
    .release = umdp_mem_release,
    .mmap = umdp_mem_mmap,
};

static struct cdev umdp_mem_cdev;
static dev_t umdp_mem_chrdev;
static struct class* umdp_mem_dev_class;

#define UDMP_MEM_CLASS_NAME "umdp"
#define UDMP_MEM_DEVICE_NAME "umdp-mem"

static int umdp_init(void) {
    devio_data.allocated_region_count = 0;
    ih_data.registered_irq_count = 0;

    int ret = alloc_chrdev_region(&umdp_mem_chrdev, 0, 1, UDMP_MEM_DEVICE_NAME);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to allocate character device (error code %d)\n", -ret);
        goto fail;
    }

    cdev_init(&umdp_mem_cdev, &umdp_mem_fops);
    umdp_mem_cdev.owner = THIS_MODULE;
    ret = kobject_set_name(&umdp_mem_cdev.kobj, UDMP_MEM_DEVICE_NAME);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to set character device name (error code %d)\n", -ret);
        goto fail_after_cdev_init;
    }

    ret = cdev_add(&umdp_mem_cdev, umdp_mem_chrdev, 1);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to add character device to system (error code %d)\n", -ret);
        goto fail_after_cdev_init;
    }

    umdp_mem_dev_class = class_create(UDMP_MEM_CLASS_NAME);
    if (IS_ERR(umdp_mem_dev_class)) {
        ret = (int) PTR_ERR(umdp_mem_dev_class);
        printk(KERN_ERR "umdp: Failed to create character device class (error code %d)\n", -ret);
        goto fail_after_cdev_init;
    }

    struct device* umdp_mem_device =
        device_create(umdp_mem_dev_class, NULL, umdp_mem_chrdev, NULL, UDMP_MEM_DEVICE_NAME);
    if (IS_ERR(umdp_mem_device)) {
        ret = (int) PTR_ERR(umdp_mem_device);
        printk(KERN_ERR "umdp: Failed to create character device (error code %d)\n", -ret);
        goto fail_after_class_create;
    }

    ih_workqueue = alloc_workqueue(UMDP_WORKQUEUE_NAME, 0, 0);
    size_t i;
    for (i = 0; i < UMDP_WORKER_COUNT; i++) {
        ih_workers[i].busy = false;
    }

    ret = genl_register_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to register netlink family (error code %d)\n", ret);
        goto fail_after_device_create;
    }

    printk(KERN_INFO "umdp: Registered netlink kernel family (id: %d)\n", umdp_genl_family.id);
    return 0;

fail_after_device_create:
    device_destroy(umdp_mem_dev_class, umdp_mem_chrdev);
fail_after_class_create:
    class_destroy(umdp_mem_dev_class);
fail_after_cdev_init:
    cdev_del(&umdp_mem_cdev);
    unregister_chrdev_region(umdp_mem_chrdev, 1);
fail:
    return ret;
}

static void umdp_exit(void) {
    int ret = genl_unregister_family(&umdp_genl_family);
    if (ret != 0) {
        printk(KERN_ERR "umdp: Failed to unregister netlink family\n");
    } else {
        printk(KERN_INFO "umdp: Unregistered netlink family\n");
    }

    destroy_workqueue(ih_workqueue);

    mutex_lock(&ih_data_mutex);

    size_t i;
    for (i = 0; i < ih_data.registered_irq_count; i++) {
        free_irq(ih_data.registered_irqs[i], &ih_data);
    }

    mutex_unlock(&ih_data_mutex);

    mutex_lock(&devio_data_mutex);

    for (i = 0; i < devio_data.allocated_region_count; i++) {
        release_region(devio_data.allocated_regions[i].start, devio_data.allocated_regions[i].size);
    }

    mutex_unlock(&devio_data_mutex);

    device_destroy(umdp_mem_dev_class, umdp_mem_chrdev);
    class_destroy(umdp_mem_dev_class);
    cdev_del(&umdp_mem_cdev);
    unregister_chrdev_region(umdp_mem_chrdev, 1);

    down_write(&client_info_lock);
    struct client_info* p;
    struct client_info* next;
    for_each_client_info_safe(p, next) {
        list_del(&p->list);
        put_pid(p->pid);
        kfree(p);
    }
    up_write(&client_info_lock);
}

module_init(umdp_init);
module_exit(umdp_exit);
