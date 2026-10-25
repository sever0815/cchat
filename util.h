#ifndef CCHAT_UTIL_H
#define CCHAT_UTIL_H

#include <stddef.h>
#include <sys/types.h>

#define CC_MAX_NICK     32
#define CC_MAX_PASSWORD 128
#define CC_MAX_MESSAGE  2000
#define CC_MAX_SERVER_NAME 64
#define CC_PAGE_SIZE    100

/* Removes leading/trailing whitespace plus CR/LF in place. */
void cc_trim(char *s);

/* Replaces tabs, CR/LF and other control characters with spaces. */
void cc_sanitize_inline(char *s);

/* Removes a trailing CR/LF only. */
void cc_strip_newline(char *s);

int cc_username_valid(const char *name);
int cc_password_valid(const char *password);
int cc_server_name_valid(const char *name);

void cc_timestamp_now(char out[32]);

int cc_mkdir_p(const char *path, mode_t mode);

/* Replaces unsafe characters in a string with '_'. */
void cc_slug(const char *in, char *out, size_t out_size);

#endif
