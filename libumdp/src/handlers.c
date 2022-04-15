#include "handlers.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "protocol.h"

int umdp_echo_handler(__attribute__((unused)) struct nl_cache_ops* _cache_ops,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    if (arg == NULL) {
        print_err("ignored unexpected echo reply\n");
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
        print_err("received echo reply without a message attribute\n");
        return NL_SKIP;
    }

    size_t message_length = nla_len(msg_attr);
    *out = malloc(message_length);
    if (*out == NULL) {
        print_err("failed to allocate memory\n");
        return NL_STOP;
    }

    memcpy(*out, nla_data(msg_attr), message_length);
    return NL_STOP;
}
