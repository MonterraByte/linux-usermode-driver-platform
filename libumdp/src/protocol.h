#ifndef UMDP_PROTOCOL_H
#define UMDP_PROTOCOL_H

#define UMDP_GENL_NAME "UMDP"
#define UMDP_GENL_VERSION 1

enum {
    UMDP_ATTR_UNSPEC = 0,
    UMDP_ATTR_MSG = 1,
    __UMDP_ATTR_MAX,
};
#define UMDP_ATTR_MAX (__UMDP_ATTR_MAX - 1)

enum {
    UMDP_CMD_UNSPEC = 0,
    UMDP_CMD_ECHO = 1,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

#endif  // UMDP_PROTOCOL_H
