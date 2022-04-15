#ifndef UMDP_H
#define UMDP_H

/// \mainpage
/// The documentation can be found in umdp.h.
///
/// The following examples are available:
/// * echo.c

/// \file

#ifdef BUILDING_UMDP
#define UMDP_PUBLIC __attribute__((visibility("default")))
#else
#define UMDP_PUBLIC
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umdp_connection umdp_connection;

/// Establish a UMDP connection
/// \return Pointer to `umdp_connection` or `NULL` in case of failure
UMDP_PUBLIC umdp_connection* umdp_connect();

/// Disconnect the specified UMDP connection
/// \param connection Pointer to `umdp_connection`
UMDP_PUBLIC void umdp_disconnect(umdp_connection* connection);

/// Send a string to the kernel and receive it back
/// \param connection `umdp_connection` to use
/// \param string String to send
/// \return Pointer to received string (should be `free()`'d by the caller) or `NULL` in case of failure
UMDP_PUBLIC char* umdp_echo(umdp_connection* connection, char* string);

#ifdef __cplusplus
}
#endif

#endif  // UMDP_H
