#ifndef CCHAT_HISTORY_H
#define CCHAT_HISTORY_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

typedef struct {
    char *nick;
    char *timestamp;
    char *text;
} cc_history_msg;

typedef struct {
    cc_history_msg *msgs;
    size_t count;
    size_t cap;
} cc_history;

void cc_history_init(cc_history *h);
void cc_history_free(cc_history *h);

int cc_history_add(cc_history *h, const char *nick,
                   const char *timestamp, const char *text);

/* Returns 0 on success (a missing file is an empty history). */
int cc_history_load(const char *path, const uint8_t key[CC_KEY_LEN],
                    cc_history *out);

int cc_history_append(const char *path, const uint8_t key[CC_KEY_LEN],
                      const char *nick, const char *timestamp,
                      const char *text);

/* Atomically rewrites the history file. */
int cc_history_save(const char *path, const uint8_t key[CC_KEY_LEN],
                    const cc_history *h);

#endif
