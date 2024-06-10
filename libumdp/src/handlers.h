#ifndef UMDP_HANDLERS_H
#define UMDP_HANDLERS_H

#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>

int umdp_echo_handler(struct nl_cache_ops* _unused, struct genl_cmd* _cmd, struct genl_info* info, void* arg);
int umdp_connect_handler(struct nl_cache_ops* _unused, struct genl_cmd* _cmd, struct genl_info* info, void* arg);
int umdp_devio_read_handler(struct nl_cache_ops* _unused, struct genl_cmd* _cmd, struct genl_info* info, void* arg);
int umdp_interrupt_handler(struct nl_cache_ops* _unused, struct genl_cmd* _cmd, struct genl_info* info, void* arg);

#endif  // UMDP_HANDLERS_H
