#ifndef UMDP_H
#define UMDP_H

#ifdef BUILDING_UMDP
    #define UMDP_PUBLIC __attribute__ ((visibility ("default")))
#else
    #define UMDP_PUBLIC
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umdp_connection umdp_connection;

UMDP_PUBLIC umdp_connection* umdp_connect();
UMDP_PUBLIC void umdp_destroy(umdp_connection* connection);

UMDP_PUBLIC void umdp_echo(umdp_connection* connection, char* string);

#ifdef __cplusplus
}
#endif

#endif  // UMDP_H
