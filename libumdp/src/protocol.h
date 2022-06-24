#ifndef UMDP_PROTOCOL_H
#define UMDP_PROTOCOL_H

#define UMDP_GENL_NAME "UMDP"
#define UMDP_GENL_VERSION 1

enum {
    UMDP_ATTR_UNSPEC __attribute__((unused)) __attribute__((unused)) = 0,
    UMDP_ATTR_MSG = 1,
    UMDP_ATTR_U8 = 2,
    UMDP_ATTR_U16 = 3,
    UMDP_ATTR_U32 = 4,
    UMDP_ATTR_U64 = 5,
    __UMDP_ATTR_MAX,
};
#define UMDP_ATTR_MAX (__UMDP_ATTR_MAX - 1)

enum {
    UMDP_CMD_UNSPEC __attribute__((unused)) __attribute__((unused)) = 0,
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

#endif  // UMDP_PROTOCOL_H
