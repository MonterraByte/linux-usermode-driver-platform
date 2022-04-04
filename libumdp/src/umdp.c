#include "umdp.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/socket.h>

#define UMDP_GENL_NAME "UMDP"

enum {
    UMDP_ATTR_UNSPEC = 0,
    UMDP_ATTR_MSG = 1,
    __UMDP_ATTR_MAX,
};
#define UMDP_ATTR_MAX (__UMDP_ATTR_MAX - 1)

static struct nla_policy umdp_policy[UMDP_ATTR_MAX + 1] = {
    [UMDP_ATTR_MSG] =
        {
            .type = NLA_NUL_STRING,
        },
};

enum {
    UMDP_CMD_UNSPEC = 0,
    UMDP_CMD_ECHO = 1,
    __UMDP_CMD_MAX,
};
#define UMDP_CMD_MAX (__UMDP_CMD_MAX - 1)

static int umdp_echo_handler(struct nl_cache_ops* _unused, struct genl_cmd* cmd, struct genl_info* info, void* arg) {
    assert(cmd->c_id == UMDP_CMD_ECHO);
    assert(info->genlhdr->cmd == UMDP_CMD_ECHO);

    if (arg == NULL) {
        return 0;
    }
    char** out = arg;

    size_t length = genlmsg_len(info->genlhdr);
    *out = malloc(length);
    if (*out == NULL) {
        return -1;  // ENOMEM ?
    }

    memcpy(*out, genlmsg_data(info->genlhdr), length);
    return 0;
}

static struct genl_cmd umdp_cmds[] = {
    {
        .c_id = UMDP_CMD_ECHO,
        .c_name = "UMDP_CMD_ECHO",
        .c_maxattr = 1,
        .c_attr_policy = umdp_policy,
        .c_msg_parser = umdp_echo_handler,
    },
};

static struct genl_ops umdp_family = {
    .o_name = UMDP_GENL_NAME,
    .o_cmds = umdp_cmds,
    .o_ncmds = sizeof(umdp_cmds) / sizeof(struct genl_cmd),
};

struct umdp_connection {
    struct nl_sock* socket;
};

umdp_connection* umdp_connect() {
    umdp_connection* connection = malloc(sizeof(umdp_connection));
    if (connection == NULL) {
        return NULL;
    }


    connection->socket = nl_socket_alloc();
    if (connection->socket == NULL) {
        goto socket_failure;
    }

    if (nl_socket_modify_cb(connection->socket, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, NULL) != 0) {
        goto failure;
    }

    // Set the socket to talk to the kernel, which has port 0
    nl_socket_set_peer_port(connection->socket, 0);

    if (genl_connect(connection->socket) != 0) {
        goto failure;
    }

    if (genl_ops_resolve(connection->socket, &umdp_family) != 0) {
        goto failure;
    }

    return connection;

failure:
    nl_socket_free(connection->socket);
socket_failure:
    free(connection);
    return NULL;
}

void umdp_destroy(umdp_connection* connection) {
    nl_socket_free(connection->socket);
    free(connection);
}

void umdp_echo(umdp_connection* connection, char* string) {
    size_t string_length = strlen(string) + 1;

    struct nl_msg* msg = nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + string_length);
    if (msg == NULL) {
        return;  // NULL;
    }

    void* user_header = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, umdp_family.o_id, 0, NLM_F_REQUEST, UMDP_CMD_ECHO, 1);
    if (user_header == NULL) {
        return;  // NULL;
    }

    void* msg_data = genlmsg_data(genlmsg_hdr(nlmsg_hdr(msg)));
    assert(user_header == msg_data);

    nlmsg_append(msg, string, string_length, 0);
    //memcpy(msg_data, string, string_length);

    printf("String length: %ld\n", string_length);
    printf("Message length: %d\n", genlmsg_len(genlmsg_hdr(nlmsg_hdr(msg))));
    assert((size_t) genlmsg_len(genlmsg_hdr(nlmsg_hdr(msg))) == string_length);

    char* reply = NULL;
    if (nl_socket_modify_cb(connection->socket, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, &reply) != 0) {
        return;
    }

    printf("Sending message\n");
    if (nl_send_auto(connection->socket, msg) != 0) {
        printf("Fail sending\n");
        return;
    }
    nlmsg_free(msg);

    printf("Waiting for response\n");
    if (nl_recvmsgs_default(connection->socket) != 0) {
        printf("Fail receiving\n");
        return;
    }
    printf("%s\n", reply);
    free(reply);
}
