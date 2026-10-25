#define _POSIX_C_SOURCE 200809L

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

void cc_strip_newline(char *s)
{
    size_t len;

    if (s == NULL)
        return;
    len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

void cc_trim(char *s)
{
    char *start;
    size_t len;

    if (s == NULL)
        return;

    cc_strip_newline(s);
    start = s;
    while (*start != '\0' && isspace((unsigned char)*start))
        start++;

    len = strlen(start);
    while (len > 0 && isspace((unsigned char)start[len - 1]))
        len--;
    start[len] = '\0';

    if (start != s)
        memmove(s, start, len + 1);
}

void cc_sanitize_inline(char *s)
{
    unsigned char *p;

    if (s == NULL)
        return;

    for (p = (unsigned char *)s; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f)
            *p = ' ';
    }
}

int cc_username_valid(const char *name)
{
    const unsigned char *p;
    size_t len;

    if (name == NULL)
        return 0;
    len = strlen(name);
    if (len == 0 || len > CC_MAX_NICK)
        return 0;

    for (p = (const unsigned char *)name; *p != '\0'; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == ':' || *p == '/' || *p == '\\')
            return 0;
    }
    return 1;
}

int cc_password_valid(const char *password)
{
    const unsigned char *p;
    size_t len;

    if (password == NULL)
        return 0;
    len = strlen(password);
    if (len < 4 || len > CC_MAX_PASSWORD)
        return 0;

    for (p = (const unsigned char *)password; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

int cc_server_name_valid(const char *name)
{
    const unsigned char *p;
    size_t len;

    if (name == NULL)
        return 0;
    len = strlen(name);
    if (len == 0 || len > CC_MAX_SERVER_NAME)
        return 0;

    for (p = (const unsigned char *)name; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f || *p == ':' || *p == '/' || *p == '\\')
            return 0;
    }
    return 1;
}

void cc_timestamp_now(char out[32])
{
    time_t now = time(NULL);
    struct tm tm_buf;

    if (localtime_r(&now, &tm_buf) == NULL) {
        snprintf(out, 32, "1970-01-01 00:00:00");
        return;
    }
    strftime(out, 32, "%Y-%m-%d %H:%M:%S", &tm_buf);
}

int cc_mkdir_p(const char *path, mode_t mode)
{
    char tmp[4096];
    char *p;
    size_t len;

    if (path == NULL || *path == '\0')
        return -1;

    len = strlen(path);
    if (len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1);

    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

void cc_slug(const char *in, char *out, size_t out_size)
{
    size_t i = 0;

    if (out_size == 0)
        return;

    if (in != NULL) {
        for (; *in != '\0' && i + 1 < out_size; in++) {
            unsigned char c = (unsigned char)*in;
            if ((c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '-' || c == '_' || c == '.') {
                out[i++] = (char)c;
            } else {
                out[i++] = '_';
            }
        }
    }
    out[i] = '\0';
}
