#define _POSIX_C_SOURCE 200809L

#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n;
#ifdef MSG_NOSIGNAL
        n = send(fd, p + off, len - off, MSG_NOSIGNAL);
#else
        n = send(fd, p + off, len - off, 0);
#endif
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/*
 * Returns 1 on success, 0 on clean EOF before any byte,
 * -1 on error or an unexpected EOF.
 */
static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;

    while (off < len) {
        ssize_t n = recv(fd, p + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return off == 0 ? 0 : -1;
        off += (size_t)n;
    }
    return 1;
}

int cc_conn_init(cc_conn_t *c, int fd, const uint8_t *secret,
                 size_t secret_len, int is_server)
{
    if (c == NULL || secret == NULL)
        return -1;

    memset(c, 0, sizeof(*c));
    c->fd = fd;

    if (pthread_mutex_init(&c->send_mu, NULL) != 0)
        return -1;

    if (is_server) {
        cc_derive_key(secret, secret_len, "cchat-net-s2c", c->send_key);
        cc_derive_key(secret, secret_len, "cchat-net-c2s", c->recv_key);
    } else {
        cc_derive_key(secret, secret_len, "cchat-net-c2s", c->send_key);
        cc_derive_key(secret, secret_len, "cchat-net-s2c", c->recv_key);
    }
    return 0;
}

void cc_conn_destroy(cc_conn_t *c)
{
    if (c == NULL)
        return;
    pthread_mutex_destroy(&c->send_mu);
    memset(c, 0, sizeof(*c));
}

int cc_conn_send(cc_conn_t *c, const void *data, size_t len)
{
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t hdr[4];
    uint32_t net_len;
    int rc = -1;

    if (c == NULL || data == NULL || len > CC_NET_MAX_PAYLOAD)
        return -1;

    if (cc_encrypt_blob(c->send_key, (const uint8_t *)data, len,
                        &blob, &blob_len) != 0)
        return -1;

    if (blob_len > UINT32_MAX) {
        free(blob);
        return -1;
    }

    net_len = htonl((uint32_t)blob_len);
    memcpy(hdr, &net_len, sizeof(hdr));

    pthread_mutex_lock(&c->send_mu);
    if (write_all(c->fd, hdr, sizeof(hdr)) == 0 &&
        write_all(c->fd, blob, blob_len) == 0) {
        rc = 0;
    }
    pthread_mutex_unlock(&c->send_mu);

    free(blob);
    return rc;
}

ssize_t cc_conn_recv(cc_conn_t *c, void *buf, size_t cap)
{
    uint8_t hdr[4];
    uint32_t net_len;
    size_t blob_len;
    uint8_t *blob = NULL;
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    int rr;
    ssize_t rc = -1;

    if (c == NULL || buf == NULL || cap == 0)
        return -1;

    rr = read_all(c->fd, hdr, sizeof(hdr));
    if (rr <= 0)
        return rr;

    memcpy(&net_len, hdr, sizeof(net_len));
    blob_len = ntohl(net_len);
    if (blob_len < CC_NONCE_LEN + CC_TAG_LEN ||
        blob_len > CC_NET_MAX_PAYLOAD + CC_NONCE_LEN + CC_TAG_LEN) {
        errno = EMSGSIZE;
        return -1;
    }

    blob = (uint8_t *)malloc(blob_len);
    if (blob == NULL)
        return -1;

    rr = read_all(c->fd, blob, blob_len);
    if (rr != 1)
        goto out;

    if (cc_decrypt_blob(c->recv_key, blob, blob_len,
                        &plain, &plain_len) != 0) {
        errno = EBADMSG;
        goto out;
    }

    if (plain_len >= cap) {
        errno = EMSGSIZE;
        goto out;
    }

    memcpy(buf, plain, plain_len);
    ((char *)buf)[plain_len] = '\0';
    rc = (ssize_t)plain_len;

out:
    free(blob);
    free(plain);
    return rc;
}
