#define _POSIX_C_SOURCE 200809L

#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* SHA-256                                                                   */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   used;
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(sha256_ctx *c, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, d, e, f, g, h, cc;
    uint32_t s0, s1, ch, maj, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];

    for (i = 0; i < 64; i++) {
        s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        ch = (e & f) ^ ((~e) & g);
        t1 = h + s1 + ch + SHA256_K[i] + w[i];
        s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->bits = 0;
    c->used = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    c->bits += (uint64_t)len * 8u;

    while (len > 0) {
        size_t room = 64 - c->used;
        size_t take = len < room ? len : room;
        memcpy(c->buf + c->used, p, take);
        c->used += take;
        p += take;
        len -= take;
        if (c->used == 64) {
            sha256_transform(c, c->buf);
            c->used = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->bits;
    int i;

    c->buf[c->used++] = 0x80;
    if (c->used > 56) {
        while (c->used < 64)
            c->buf[c->used++] = 0;
        sha256_transform(c, c->buf);
        c->used = 0;
    }
    while (c->used < 56)
        c->buf[c->used++] = 0;

    for (i = 7; i >= 0; i--)
        c->buf[56 + (7 - i)] = (uint8_t)(bits >> (i * 8));

    sha256_transform(c, c->buf);

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }
    memset(c, 0, sizeof(*c));
}

void cc_sha256(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ------------------------------------------------------------------------- */
/* HMAC-SHA256                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    sha256_ctx inner;
    sha256_ctx outer;
} hmac_ctx;

static void hmac_init(hmac_ctx *h, const uint8_t *key, size_t key_len)
{
    uint8_t block[64];
    uint8_t pad[64];
    uint8_t tmp[32];
    size_t i;

    memset(block, 0, sizeof(block));
    if (key_len > sizeof(block)) {
        cc_sha256(key, key_len, tmp);
        memcpy(block, tmp, sizeof(tmp));
    } else if (key_len > 0) {
        memcpy(block, key, key_len);
    }

    for (i = 0; i < 64; i++)
        pad[i] = block[i] ^ 0x36;
    sha256_init(&h->inner);
    sha256_update(&h->inner, pad, 64);

    for (i = 0; i < 64; i++)
        pad[i] = block[i] ^ 0x5c;
    sha256_init(&h->outer);
    sha256_update(&h->outer, pad, 64);

    memset(block, 0, sizeof(block));
    memset(pad, 0, sizeof(pad));
    memset(tmp, 0, sizeof(tmp));
}

static void hmac_update(hmac_ctx *h, const void *data, size_t len)
{
    sha256_update(&h->inner, data, len);
}

static void hmac_final(hmac_ctx *h, uint8_t out[32])
{
    uint8_t tmp[32];
    sha256_final(&h->inner, tmp);
    sha256_update(&h->outer, tmp, sizeof(tmp));
    sha256_final(&h->outer, out);
    memset(tmp, 0, sizeof(tmp));
    memset(h, 0, sizeof(*h));
}

void cc_hmac_sha256(const uint8_t *key, size_t key_len,
                    const void *data, size_t len, uint8_t out[32])
{
    hmac_ctx h;
    hmac_init(&h, key, key_len);
    hmac_update(&h, data, len);
    hmac_final(&h, out);
}

void cc_derive_key(const uint8_t *secret, size_t secret_len,
                   const char *label, uint8_t out[CC_KEY_LEN])
{
    cc_hmac_sha256(secret, secret_len, label, strlen(label), out);
}

/* ------------------------------------------------------------------------- */
/* PBKDF2-HMAC-SHA256                                                        */
/* ------------------------------------------------------------------------- */

int cc_pbkdf2_sha256(const char *password, const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint8_t *out, size_t out_len)
{
    uint8_t u[32], t[32];
    uint8_t *block;
    uint32_t i;
    size_t done = 0;
    size_t pass_len;

    if (password == NULL || out == NULL || iterations == 0)
        return -1;

    pass_len = strlen(password);
    block = (uint8_t *)malloc(salt_len + 4);
    if (block == NULL)
        return -1;

    for (i = 1; done < out_len; i++) {
        hmac_ctx h;
        uint32_t j;
        size_t take;

        memcpy(block, salt, salt_len);
        block[salt_len]     = (uint8_t)(i >> 24);
        block[salt_len + 1] = (uint8_t)(i >> 16);
        block[salt_len + 2] = (uint8_t)(i >> 8);
        block[salt_len + 3] = (uint8_t)i;

        hmac_init(&h, (const uint8_t *)password, pass_len);
        hmac_update(&h, block, salt_len + 4);
        hmac_final(&h, u);
        memcpy(t, u, sizeof(t));

        for (j = 1; j < iterations; j++) {
            hmac_init(&h, (const uint8_t *)password, pass_len);
            hmac_update(&h, u, sizeof(u));
            hmac_final(&h, u);
            {
                size_t k;
                for (k = 0; k < sizeof(t); k++)
                    t[k] ^= u[k];
            }
        }

        take = out_len - done;
        if (take > sizeof(t))
            take = sizeof(t);
        memcpy(out + done, t, take);
        done += take;
    }

    free(block);
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    return 0;
}

/* ------------------------------------------------------------------------- */
/* ChaCha20 (RFC 8439)                                                       */
/* ------------------------------------------------------------------------- */

static uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define QR(a, b, c, d)                    \
    do {                                  \
        (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
        (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
        (a) += (b); (d) ^= (a); (d) = rotl32((d), 8);  \
        (c) += (d); (b) ^= (c); (b) = rotl32((b), 7);  \
    } while (0)

static void chacha20_block(const uint8_t key[CC_KEY_LEN],
                           const uint8_t nonce[CC_NONCE_LEN],
                           uint32_t counter, uint8_t out[64])
{
    uint32_t x[16], initial[16];
    int i;

    initial[0] = 0x61707865u;
    initial[1] = 0x3320646eu;
    initial[2] = 0x79622d32u;
    initial[3] = 0x6b206574u;
    for (i = 0; i < 8; i++)
        initial[4 + i] = load32_le(key + i * 4);
    initial[12] = counter;
    initial[13] = load32_le(nonce);
    initial[14] = load32_le(nonce + 4);
    initial[15] = load32_le(nonce + 8);

    memcpy(x, initial, sizeof(x));

    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; i++)
        store32_le(out + i * 4, x[i] + initial[i]);

    memset(x, 0, sizeof(x));
    memset(initial, 0, sizeof(initial));
}

void cc_chacha20_xor(const uint8_t key[CC_KEY_LEN],
                     const uint8_t nonce[CC_NONCE_LEN], uint32_t counter,
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t stream[64];
    size_t offset = 0;

    while (offset < len) {
        size_t take = len - offset;
        size_t i;

        if (take > sizeof(stream))
            take = sizeof(stream);

        chacha20_block(key, nonce, counter++, stream);
        for (i = 0; i < take; i++)
            out[offset + i] = in[offset + i] ^ stream[i];
        offset += take;
    }

    memset(stream, 0, sizeof(stream));
}

/* ------------------------------------------------------------------------- */
/* Encrypt-then-MAC blobs                                                    */
/* ------------------------------------------------------------------------- */

int cc_encrypt_blob(const uint8_t key[CC_KEY_LEN],
                    const uint8_t *plain, size_t len,
                    uint8_t **out, size_t *out_len)
{
    uint8_t enc_key[32], mac_key[32];
    uint8_t *blob;
    uint8_t *ct;
    uint8_t *tag;
    hmac_ctx h;
    size_t total;

    if (out == NULL || out_len == NULL)
        return -1;
    if (len > SIZE_MAX - CC_NONCE_LEN - CC_TAG_LEN)
        return -1;

    total = CC_NONCE_LEN + len + CC_TAG_LEN;
    blob = (uint8_t *)malloc(total);
    if (blob == NULL)
        return -1;

    if (cc_random_bytes(blob, CC_NONCE_LEN) != 0)
        goto fail;

    ct  = blob + CC_NONCE_LEN;
    tag = ct + len;

    cc_derive_key(key, CC_KEY_LEN, "cchat-blob-enc", enc_key);
    cc_derive_key(key, CC_KEY_LEN, "cchat-blob-mac", mac_key);

    cc_chacha20_xor(enc_key, blob, 1, plain, ct, len);

    hmac_init(&h, mac_key, sizeof(mac_key));
    hmac_update(&h, blob, CC_NONCE_LEN + len);
    hmac_final(&h, tag);

    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));

    *out = blob;
    *out_len = total;
    return 0;

fail:
    free(blob);
    return -1;
}

int cc_decrypt_blob(const uint8_t key[CC_KEY_LEN],
                    const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len)
{
    uint8_t enc_key[32], mac_key[32], expected[32];
    const uint8_t *ct;
    const uint8_t *tag;
    uint8_t *plain;
    hmac_ctx h;
    size_t len;

    if (in == NULL || out == NULL || out_len == NULL ||
        in_len < CC_NONCE_LEN + CC_TAG_LEN)
        return -1;

    len = in_len - CC_NONCE_LEN - CC_TAG_LEN;
    ct  = in + CC_NONCE_LEN;
    tag = ct + len;

    cc_derive_key(key, CC_KEY_LEN, "cchat-blob-mac", mac_key);
    hmac_init(&h, mac_key, sizeof(mac_key));
    hmac_update(&h, in, CC_NONCE_LEN + len);
    hmac_final(&h, expected);

    if (!cc_constant_time_eq(expected, tag, CC_TAG_LEN)) {
        memset(mac_key, 0, sizeof(mac_key));
        return -1;
    }

    plain = (uint8_t *)malloc(len + 1);
    if (plain == NULL) {
        memset(mac_key, 0, sizeof(mac_key));
        return -1;
    }

    cc_derive_key(key, CC_KEY_LEN, "cchat-blob-enc", enc_key);
    cc_chacha20_xor(enc_key, in, 1, ct, plain, len);
    plain[len] = '\0';

    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));

    *out = plain;
    *out_len = len;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Random, comparison, hex                                                   */
/* ------------------------------------------------------------------------- */

int cc_random_bytes(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    int fd;
    size_t off = 0;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }

    close(fd);
    return 0;
}

int cc_constant_time_eq(const void *a, const void *b, size_t len)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++)
        diff |= (uint8_t)(x[i] ^ y[i]);
    return diff == 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

size_t cc_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2]     = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
    return len * 2;
}

int cc_hex_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t len, i;

    if (in == NULL || out == NULL || out_len == NULL)
        return -1;

    len = strlen(in);
    if ((len & 1u) != 0 || len / 2 > out_cap)
        return -1;

    for (i = 0; i < len / 2; i++) {
        int hi = hex_nibble(in[i * 2]);
        int lo = hex_nibble(in[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = len / 2;
    return 0;
}
