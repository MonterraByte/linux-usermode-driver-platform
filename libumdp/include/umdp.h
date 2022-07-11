#ifndef UMDP_H
#define UMDP_H

/// \mainpage
/// The documentation can be found in umdp.h.
///
/// The following examples are available:
/// * devio.c
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

#include <stdint.h>

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


UMDP_PUBLIC int umdp_devio_request(umdp_connection* connection, uint64_t port);
UMDP_PUBLIC int umdp_devio_release(umdp_connection* connection, uint64_t port);

/// Read a byte from the specified port
/// \param connection `umdp_connection` to use
/// \param port Port to read from
/// \param out Pointer to where the read value should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_read_u8(umdp_connection* connection, uint64_t port, uint8_t* out);

/// Read a 2 byte value from the specified port
/// \param connection `umdp_connection` to use
/// \param port Port to read from
/// \param out Pointer to where the read value should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_read_u16(umdp_connection* connection, uint64_t port, uint16_t* out);

/// Read a 4 byte value from the specified port
/// \param connection `umdp_connection` to use
/// \param port Port to read from
/// \param out Pointer to where the read value should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_read_u32(umdp_connection* connection, uint64_t port, uint32_t* out);


/// Write a byte to the specified port
/// \param connection `umdp_connection` to use
/// \param port Port to write to
/// \param value Value to write
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_write_u8(umdp_connection* connection, uint64_t port, uint8_t value);

/// Write a 2 byte value to the specified port
/// \param connection `umdp_connection` to use
/// \param port Port to write to
/// \param value Value to write
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_write_u16(umdp_connection* connection, uint64_t port, uint16_t value);

/// Write a 4 byte value to the specified port
/// \param connection `umdp_connection` to use
/// \param port Port to write to
/// \param value Value to write
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_write_u32(umdp_connection* connection, uint64_t port, uint32_t value);

UMDP_PUBLIC int umdp_interrupt_subscribe(umdp_connection* connection, uint32_t irq);
UMDP_PUBLIC int umdp_interrupt_unsubscribe(umdp_connection* connection, uint32_t irq);
UMDP_PUBLIC int umdp_receive_interrupt(umdp_connection* connection, uint32_t* out);

#ifdef __cplusplus
}
#endif

#endif  // UMDP_H
