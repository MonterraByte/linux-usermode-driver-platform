#include "handlers.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

int umdp_echo_handler(struct nl_cache_ops* _unused, struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    if (arg == NULL) {
        return 0;
    }
    char** out = arg;

    struct nlattr* msg_attr = NULL;
    for (int i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        struct nlattr* attr = info->attrs[i];
        if (attr == NULL) {
            continue;
        }

        if (attr->nla_type == UMDP_ATTR_MSG) {
            msg_attr = attr;
            break;
        }
    }

    if (msg_attr == NULL) {
        return -EINVAL;
    }

    size_t message_length = nla_len(msg_attr);
    *out = malloc(message_length);
    if (*out == NULL) {
        return -ENOMEM;
    }

    memcpy(*out, nla_data(msg_attr), message_length);
    return 0;
}
