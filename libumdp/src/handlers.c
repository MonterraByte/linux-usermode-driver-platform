#include "handlers.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "protocol.h"

static struct nlattr* find_attribute(struct nlattr** attributes, int type) {
    for (int i = 0; i < UMDP_ATTR_MAX + 1; i++) {
        struct nlattr* attribute = attributes[i];
        if (attribute == NULL) {
            continue;
        }

        if (nla_type(attribute) == type) {
            return attribute;
        }
    }
    return NULL;
}

int umdp_echo_handler(__attribute__((unused)) struct nl_cache_ops* _cache_ops,
    __attribute__((unused)) struct genl_cmd* _cmd, struct genl_info* info, void* arg) {
    if (arg == NULL) {
        print_err("ignored unexpected echo reply\n");
        return NL_SKIP;
    }
    char** out = arg;

    struct nlattr* msg_attr = find_attribute(info->attrs, UMDP_ATTR_MSG);
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
