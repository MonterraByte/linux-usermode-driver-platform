#ifndef UMDP_H
#define UMDP_H

/// \mainpage
/// The documentation can be found in umdp.h.
///
/// The following examples are available:
/// * devio.c
/// * echo.c
/// * interrupts.c
/// * timer.c

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

/// Establish a connection to the kernel.
///
/// The `umdp` kernel module needs to be loaded before this function is called.
/// The returned `umdp_connection` should be destroyed after its last use using `umdp_disconnect()`.
///
/// \return Pointer to `umdp_connection` or `NULL` in case of failure
UMDP_PUBLIC umdp_connection* umdp_connect(void);

/// Disconnect the specified UMDP connection, freeing all associated resources.
///
/// This function also frees the `umdp_connection` struct.
///
/// \param connection Pointer to `umdp_connection`
UMDP_PUBLIC void umdp_disconnect(umdp_connection* connection);

/// Send a string to the kernel and receive it back.
///
/// \param connection `umdp_connection` to use
/// \param string String to send
/// \return Pointer to received string (should be `free()`'d by the caller) or `NULL` in case of failure
UMDP_PUBLIC char* umdp_echo(umdp_connection* connection, char* string);


/// Request access to an I/O port region.
///
/// If the I/O port region is already in use by another driver, it will be released beforehand.
/// Linux requires that I/O regions be released as a whole, so if the I/O region you want is already in use,
/// you must specify it in its entirety, even if you don't intend to use all of it.
///
/// Make sure to release it when it's not necessary anymore using `umdp_devio_release()`.
///
/// \param connection `umdp_connection` to use
/// \param start The first I/O port of the desired region
/// \param size The size of the region (must be greater than 0)
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_request(umdp_connection* connection, uint64_t start, uint32_t size);

/// Release an I/O port region.
///
/// It must have been previously requested using `umdp_devio_request()`.
///
/// \param connection `umdp_connection` to use
/// \param start The first I/O port of the desired region
/// \param size The size of the region (must be greater than 0)
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_release(umdp_connection* connection, uint64_t start, uint32_t size);


/// Read a byte from the specified port.
///
/// \param connection `umdp_connection` to use
/// \param port Port to read from
/// \param out Pointer to where the read value should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_read_u8(umdp_connection* connection, uint64_t port, uint8_t* out);

/// Read a 2 byte value from the specified port.
///
/// \param connection `umdp_connection` to use
/// \param port Port to read from
/// \param out Pointer to where the read value should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_read_u16(umdp_connection* connection, uint64_t port, uint16_t* out);

/// Read a 4 byte value from the specified port.
///
/// \param connection `umdp_connection` to use
/// \param port Port to read from
/// \param out Pointer to where the read value should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_read_u32(umdp_connection* connection, uint64_t port, uint32_t* out);


/// Write a byte to the specified port.
///
/// \param connection `umdp_connection` to use
/// \param port Port to write to
/// \param value Value to write
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_write_u8(umdp_connection* connection, uint64_t port, uint8_t value);

/// Write a 2 byte value to the specified port.
///
/// \param connection `umdp_connection` to use
/// \param port Port to write to
/// \param value Value to write
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_write_u16(umdp_connection* connection, uint64_t port, uint16_t value);

/// Write a 4 byte value to the specified port.
///
/// \param connection `umdp_connection` to use
/// \param port Port to write to
/// \param value Value to write
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_devio_write_u32(umdp_connection* connection, uint64_t port, uint32_t value);


/// Subscribe to interrupts from the specified IRQ line.
///
/// The IRQ line must either be free, or in shared mode.
///
/// \param connection `umdp_connection` to use
/// \param irq IRQ line to subscribe to
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_interrupt_subscribe(umdp_connection* connection, uint32_t irq);

/// Unsubscribe from interrupts from the specified IRQ line.
///
/// \param connection `umdp_connection` to use
/// \param irq IRQ line to subscribe to
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_interrupt_unsubscribe(umdp_connection* connection, uint32_t irq);

/// Receive an interrupt notification from any of the subscribed IRQ lines.
///
/// \param connection `umdp_connection` to use
/// \param out Pointer to where the IRQ number should be stored
/// \return 0 in case of success, a non-zero value in case of failure
UMDP_PUBLIC int umdp_receive_interrupt(umdp_connection* connection, uint32_t* out);

UMDP_PUBLIC const char* umdp_strerror(int error);

#ifdef __cplusplus
}
#endif

#endif  // UMDP_H
