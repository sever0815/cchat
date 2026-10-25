#ifndef CCHAT_NET_H
#define CCHAT_NET_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "crypto.h"

#define CC_NET_MAX_PAYLOAD (1024 * 1024)

typedef struct {
    int fd;
    uint8_t send_key[CC_KEY_LEN];
    uint8_t recv_key[CC_KEY_LEN];
    pthread_mutex_t send_mu;
} cc_conn_t;

/* is_server selects the traffic direction keys. Returns 0 on success. */
int cc_conn_init(cc_conn_t *c, int fd, const uint8_t *secret,
                 size_t secret_len, int is_server);
void cc_conn_destroy(cc_conn_t *c);

/* Returns 0 on success, -1 on error. */
int cc_conn_send(cc_conn_t *c, const void *data, size_t len);

/*
 * Returns payload length (>= 0), 0 on clean connection close,
 * or -1 on error/timeout. The output is NUL-terminated when cap > 0.
 */
ssize_t cc_conn_recv(cc_conn_t *c, void *buf, size_t cap);

#endif
