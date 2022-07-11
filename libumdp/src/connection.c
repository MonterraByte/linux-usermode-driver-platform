#include "connection.h"

void umdp_connection_init(umdp_connection* connection) {
    connection->socket = NULL;
    connection->received_echo = NULL;
    connection->received_devio_value.type = DEVIO_VALUE_NONE;
}
