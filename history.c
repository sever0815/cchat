#define _POSIX_C_SOURCE 200809L

#include "history.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"

#define HISTORY_HEADER "CCHAT-HISTORY-V1"
#define RECORD_PREFIX  "CC1:"

static char *dup_string(const char *s)
{
    size_t len;
    char *p;

    if (s == NULL)
        s = "";
    len = strlen(s);
    p = (char *)malloc(len + 1);
    if (p != NULL)
        memcpy(p, s, len + 1);
    return p;
}

void cc_history_init(cc_history *h)
{
    if (h != NULL) {
        h->msgs = NULL;
        h->count = 0;
        h->cap = 0;
    }
}

void cc_history_free(cc_history *h)
{
    size_t i;

    if (h == NULL)
        return;
    for (i = 0; i < h->count; i++) {
        free(h->msgs[i].nick);
        free(h->msgs[i].timestamp);
        free(h->msgs[i].text);
    }
    free(h->msgs);
    h->msgs = NULL;
    h->count = 0;
    h->cap = 0;
}

int cc_history_add(cc_history *h, const char *nick,
                   const char *timestamp, const char *text)
{
    cc_history_msg *m;

    if (h == NULL)
        return -1;

    if (h->count == h->cap) {
        size_t new_cap = h->cap == 0 ? 64 : h->cap * 2;
        cc_history_msg *new_msgs;

        if (new_cap < h->cap || new_cap > SIZE_MAX / sizeof(*new_msgs))
            return -1;
        new_msgs = (cc_history_msg *)realloc(h->msgs, new_cap * sizeof(*new_msgs));
        if (new_msgs == NULL)
            return -1;
        h->msgs = new_msgs;
        h->cap = new_cap;
    }

    m = &h->msgs[h->count];
    m->nick = dup_string(nick);
    m->timestamp = dup_string(timestamp);
    m->text = dup_string(text);
    if (m->nick == NULL || m->timestamp == NULL || m->text == NULL) {
        free(m->nick);
        free(m->timestamp);
        free(m->text);
        return -1;
    }

    h->count++;
    return 0;
}

static int parse_record(uint8_t *plain, size_t len,
                        const char **nick, const char **timestamp,
                        const char **text)
{
    char *p1, *p2;

    if (len == 0)
        return -1;
    plain[len] = '\0'; /* decrypt_blob reserves one extra byte */

    p1 = strchr((char *)plain, '\t');
    if (p1 == NULL)
        return -1;
    *p1 = '\0';
    p2 = strchr(p1 + 1, '\t');
    if (p2 == NULL)
        return -1;
    *p2 = '\0';

    *nick = (const char *)plain;
    *timestamp = p1 + 1;
    *text = p2 + 1;
    return 0;
}

int cc_history_load(const char *path, const uint8_t key[CC_KEY_LEN],
                    cc_history *out)
{
    FILE *f;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    int rc = 0;

    if (path == NULL || out == NULL)
        return -1;

    cc_history_init(out);
    f = fopen(path, "rb");
    if (f == NULL) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }

    while ((line_len = getline(&line, &line_cap, f)) >= 0) {
        char *p;
        size_t hex_len;
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        const char *nick, *timestamp, *text;

        cc_strip_newline(line);
        if (line[0] == '\0' || strcmp(line, HISTORY_HEADER) == 0)
            continue;
        if (strncmp(line, RECORD_PREFIX, strlen(RECORD_PREFIX)) != 0) {
            rc = -1;
            break;
        }

        p = line + strlen(RECORD_PREFIX);
        hex_len = strlen(p);
        if (hex_len == 0 || (hex_len & 1u) != 0) {
            rc = -1;
            break;
        }
        blob = (uint8_t *)malloc(hex_len / 2);
        if (blob == NULL) {
            rc = -1;
            break;
        }
        if (cc_hex_decode(p, blob, hex_len / 2, &blob_len) != 0 ||
            cc_decrypt_blob(key, blob, blob_len, &plain, &plain_len) != 0) {
            free(blob);
            rc = -1;
            break;
        }
        free(blob);

        if (parse_record(plain, plain_len, &nick, &timestamp, &text) != 0) {
            free(plain);
            rc = -1;
            break;
        }

        if (cc_history_add(out, nick, timestamp, text) != 0) {
            free(plain);
            rc = -1;
            break;
        }
        free(plain);
    }

    if (ferror(f))
        rc = -1;

    free(line);
    fclose(f);

    if (rc != 0)
        cc_history_free(out);
    return rc;
}

static int write_record(FILE *f, const uint8_t key[CC_KEY_LEN],
                        const char *nick, const char *timestamp,
                        const char *text)
{
    size_t nick_len = strlen(nick);
    size_t ts_len = strlen(timestamp);
    size_t text_len = strlen(text);
    size_t plain_len;
    uint8_t *plain = NULL;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    char *hex = NULL;
    size_t hex_len;
    int rc = -1;

    if (nick_len > SIZE_MAX - ts_len - text_len - 2)
        return -1;
    plain_len = nick_len + ts_len + text_len + 2;
    plain = (uint8_t *)malloc(plain_len);
    if (plain == NULL)
        return -1;

    memcpy(plain, nick, nick_len);
    plain[nick_len] = '\t';
    memcpy(plain + nick_len + 1, timestamp, ts_len);
    plain[nick_len + 1 + ts_len] = '\t';
    memcpy(plain + nick_len + 1 + ts_len + 1, text, text_len);

    if (cc_encrypt_blob(key, plain, plain_len, &blob, &blob_len) != 0)
        goto out;

    hex_len = blob_len * 2;
    hex = (char *)malloc(hex_len + 1);
    if (hex == NULL)
        goto out;
    cc_hex_encode(blob, blob_len, hex);

    if (fprintf(f, "%s%s\n", RECORD_PREFIX, hex) < 0)
        goto out;

    rc = 0;

out:
    free(plain);
    free(blob);
    free(hex);
    return rc;
}

int cc_history_append(const char *path, const uint8_t key[CC_KEY_LEN],
                      const char *nick, const char *timestamp,
                      const char *text)
{
    FILE *f;
    struct stat st;
    int need_header = 1;
    int rc;

    if (path == NULL || nick == NULL || timestamp == NULL || text == NULL)
        return -1;

    if (stat(path, &st) == 0 && st.st_size > 0)
        need_header = 0;

    f = fopen(path, "ab");
    if (f == NULL)
        return -1;

    if (need_header && fprintf(f, "%s\n", HISTORY_HEADER) < 0) {
        fclose(f);
        return -1;
    }

    rc = write_record(f, key, nick, timestamp, text);
    if (rc == 0) {
        if (fflush(f) != 0)
            rc = -1;
        else
            (void)fsync(fileno(f));
    }

    if (fclose(f) != 0)
        rc = -1;
    return rc;
}

int cc_history_save(const char *path, const uint8_t key[CC_KEY_LEN],
                    const cc_history *h)
{
    char *tmp_path = NULL;
    size_t path_len;
    FILE *f = NULL;
    size_t i;
    int rc = -1;

    if (path == NULL || h == NULL)
        return -1;

    path_len = strlen(path);
    if (path_len > SIZE_MAX - 64)
        return -1;
    tmp_path = (char *)malloc(path_len + 64);
    if (tmp_path == NULL)
        return -1;
    snprintf(tmp_path, path_len + 64, "%s.tmp.%ld", path, (long)getpid());

    f = fopen(tmp_path, "wb");
    if (f == NULL)
        goto out;

    if (fprintf(f, "%s\n", HISTORY_HEADER) < 0)
        goto out;

    for (i = 0; i < h->count; i++) {
        if (write_record(f, key, h->msgs[i].nick,
                         h->msgs[i].timestamp, h->msgs[i].text) != 0)
            goto out;
    }

    if (fflush(f) != 0)
        goto out;
    if (fsync(fileno(f)) != 0)
        goto out;
    if (fclose(f) != 0) {
        f = NULL;
        goto out;
    }
    f = NULL;

    if (chmod(tmp_path, 0600) != 0 && errno != EPERM)
        goto out;
    if (rename(tmp_path, path) != 0)
        goto out;

    rc = 0;

out:
    if (f != NULL)
        fclose(f);
    if (rc != 0)
        unlink(tmp_path);
    free(tmp_path);
    return rc;
}
