#ifndef CCHAT_CRYPTO_H
#define CCHAT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CC_KEY_LEN   32
#define CC_NONCE_LEN 12
#define CC_TAG_LEN   32

/* SHA-256 / HMAC-SHA256 */
void cc_sha256(const void *data, size_t len, uint8_t out[32]);
void cc_hmac_sha256(const uint8_t *key, size_t key_len,
                    const void *data, size_t len, uint8_t out[32]);

/* PBKDF2-HMAC-SHA256 */
int cc_pbkdf2_sha256(const char *password, const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint8_t *out, size_t out_len);

/* HMAC-SHA256(secret, label) */
void cc_derive_key(const uint8_t *secret, size_t secret_len,
                   const char *label, uint8_t out[CC_KEY_LEN]);

/* ChaCha20 (RFC 8439), 96-bit nonce, 32-bit block counter. */
void cc_chacha20_xor(const uint8_t key[CC_KEY_LEN],
                     const uint8_t nonce[CC_NONCE_LEN], uint32_t counter,
                     const uint8_t *in, uint8_t *out, size_t len);

/*
 * Encrypt-then-MAC blob:
 *   nonce[12] || ciphertext[len] || tag[32]
 * Keys for encryption and authentication are derived from the supplied key.
 * On success *out is malloc()ed and must be free()d.
 */
int cc_encrypt_blob(const uint8_t key[CC_KEY_LEN],
                    const uint8_t *plain, size_t len,
                    uint8_t **out, size_t *out_len);

/* Returns a malloc()ed, NUL-terminated buffer. */
int cc_decrypt_blob(const uint8_t key[CC_KEY_LEN],
                    const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len);

int cc_random_bytes(void *buf, size_t len);
int cc_constant_time_eq(const void *a, const void *b, size_t len);

/* out must hold 2*len + 1 bytes. Returns number of hex characters written. */
size_t cc_hex_encode(const uint8_t *in, size_t len, char *out);
/* Returns 0 on success, -1 on invalid input or not enough space. */
int cc_hex_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
