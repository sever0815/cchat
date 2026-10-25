#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto.h"
#include "history.h"
#include "net.h"
#include "util.h"

/* ========================================================================== */
/* Настройки сервера.                                                         */
/*                                                                            */
/* SHARED_SECRET должен быть ОДИНАКОВЫМ здесь и в client.c!                  */
/* SERVER_PORT должен быть ОДИНАКОВЫМ здесь и в client.c (или укажите порт   */
/* вручную при добавлении сервера в клиенте).                                */
/* ========================================================================== */

#define SERVER_PORT   5555
#define SHARED_SECRET "CHANGE-ME-cchat-shared-secret-please-32-bytes-minimum"

#define DATA_DIR     "data"
#define USERS_FILE   DATA_DIR "/users.db"
#define HISTORY_FILE DATA_DIR "/chat.log.enc"

#define PBKDF2_ITERS 80000

typedef struct client {
    int fd;
    cc_conn_t conn;
    char username[CC_MAX_NICK + 1];
    int authenticated;
    int joined;
    struct client *next;
} client_t;

static pthread_mutex_t g_clients_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_history_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_accounts_mu = PTHREAD_MUTEX_INITIALIZER;
static client_t *g_clients = NULL;

static void file_key(uint8_t out[CC_KEY_LEN])
{
    cc_derive_key((const uint8_t *)SHARED_SECRET, strlen(SHARED_SECRET),
                  "cchat-file-v1", out);
}

static int send_fmt(cc_conn_t *conn, const char *fmt, ...)
{
    char buf[8192];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0)
        return -1;
    if ((size_t)n >= sizeof(buf)) {
        static const char too_long[] = "ERR\tСлишком длинное сообщение";
        return cc_conn_send(conn, too_long, sizeof(too_long) - 1);
    }
    return cc_conn_send(conn, buf, (size_t)n);
}

static int send_error(cc_conn_t *conn, const char *text)
{
    return send_fmt(conn, "ERR\t%s", text);
}

/* ------------------------------------------------------------------------- */
/* Файлы данных                                                              */
/* ------------------------------------------------------------------------- */

static int ensure_data_files(void)
{
    int fd;

    if (cc_mkdir_p(DATA_DIR, 0700) != 0) {
        fprintf(stderr, "Не удалось создать каталог %s: %s\n",
                DATA_DIR, strerror(errno));
        return -1;
    }
    (void)chmod(DATA_DIR, 0700);

    fd = open(USERS_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        fprintf(stderr, "Не удалось открыть %s: %s\n",
                USERS_FILE, strerror(errno));
        return -1;
    }
    close(fd);

    fd = open(HISTORY_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        fprintf(stderr, "Не удалось открыть %s: %s\n",
                HISTORY_FILE, strerror(errno));
        return -1;
    }
    close(fd);

    (void)chmod(USERS_FILE, 0600);
    (void)chmod(HISTORY_FILE, 0600);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Аккаунты                                                                   */
/* ------------------------------------------------------------------------- */

static int account_exists_locked(const char *username)
{
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;

    f = fopen(USERS_FILE, "r");
    if (f == NULL)
        return 0;

    while ((n = getline(&line, &cap, f)) >= 0) {
        char *colon;
        (void)n;
        cc_strip_newline(line);
        colon = strchr(line, ':');
        if (colon == NULL)
            continue;
        *colon = '\0';
        if (strcmp(line, username) == 0) {
            found = 1;
            break;
        }
    }

    free(line);
    fclose(f);
    return found;
}

static int register_account(const char *username, const char *password,
                            char *err, size_t err_size)
{
    uint8_t salt[16];
    uint8_t hash[32];
    char salt_hex[33];
    char hash_hex[65];
    FILE *f;
    int rc = -1;

    pthread_mutex_lock(&g_accounts_mu);

    if (account_exists_locked(username)) {
        snprintf(err, err_size, "Этот ник уже занят");
        goto out;
    }

    if (cc_random_bytes(salt, sizeof(salt)) != 0 ||
        cc_pbkdf2_sha256(password, salt, sizeof(salt),
                         PBKDF2_ITERS, hash, sizeof(hash)) != 0) {
        snprintf(err, err_size, "Внутренняя ошибка сервера");
        goto out;
    }

    cc_hex_encode(salt, sizeof(salt), salt_hex);
    cc_hex_encode(hash, sizeof(hash), hash_hex);

    f = fopen(USERS_FILE, "ab");
    if (f == NULL) {
        snprintf(err, err_size, "Не удалось сохранить аккаунт");
        goto out;
    }
    if (fprintf(f, "%s:%s:%s\n", username, salt_hex, hash_hex) < 0) {
        fclose(f);
        snprintf(err, err_size, "Не удалось сохранить аккаунт");
        goto out;
    }
    if (fflush(f) != 0)
        (void)0;
    (void)fsync(fileno(f));
    if (fclose(f) != 0) {
        snprintf(err, err_size, "Не удалось сохранить аккаунт");
        goto out;
    }
    (void)chmod(USERS_FILE, 0600);

    rc = 0;

out:
    memset(salt, 0, sizeof(salt));
    memset(hash, 0, sizeof(hash));
    pthread_mutex_unlock(&g_accounts_mu);
    return rc;
}

static int login_account(const char *username, const char *password)
{
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int ok = 0;
    uint8_t salt[16];
    uint8_t expected[32];
    uint8_t actual[32];
    int found = 0;

    pthread_mutex_lock(&g_accounts_mu);

    f = fopen(USERS_FILE, "r");
    if (f != NULL) {
        while ((n = getline(&line, &cap, f)) >= 0) {
            char *c1, *c2;
            size_t salt_len = 0, hash_len = 0;
            (void)n;
            cc_strip_newline(line);
            c1 = strchr(line, ':');
            if (c1 == NULL)
                continue;
            *c1 = '\0';
            if (strcmp(line, username) != 0)
                continue;
            c2 = strchr(c1 + 1, ':');
            if (c2 == NULL)
                continue;
            *c2 = '\0';

            if (cc_hex_decode(c1 + 1, salt, sizeof(salt), &salt_len) == 0 &&
                cc_hex_decode(c2 + 1, expected, sizeof(expected), &hash_len) == 0 &&
                salt_len == sizeof(salt) && hash_len == sizeof(expected)) {
                found = 1;
            }
            break;
        }
        free(line);
        fclose(f);
    }

    if (found) {
        if (cc_pbkdf2_sha256(password, salt, sizeof(salt),
                             PBKDF2_ITERS, actual, sizeof(actual)) == 0 &&
            cc_constant_time_eq(actual, expected, sizeof(actual))) {
            ok = 1;
        }
    } else {
        /* Не раскрываем существование ника по времени ответа. */
        static const uint8_t dummy_salt[16] = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
        };
        (void)cc_pbkdf2_sha256(password, dummy_salt, sizeof(dummy_salt),
                               PBKDF2_ITERS, actual, sizeof(actual));
    }

    memset(salt, 0, sizeof(salt));
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    pthread_mutex_unlock(&g_accounts_mu);
    return ok;
}

/* ------------------------------------------------------------------------- */
/* История и рассылка                                                        */
/* ------------------------------------------------------------------------- */

static int send_history(client_t *c)
{
    uint8_t key[CC_KEY_LEN];
    cc_history h;
    size_t i;
    int rc = -1;

    file_key(key);

    pthread_mutex_lock(&g_history_mu);
    if (cc_history_load(HISTORY_FILE, key, &h) != 0) {
        pthread_mutex_unlock(&g_history_mu);
        memset(key, 0, sizeof(key));
        send_error(&c->conn, "Не удалось прочитать историю на сервере");
        return -1;
    }
    pthread_mutex_unlock(&g_history_mu);

    if (send_fmt(&c->conn, "HISTCOUNT\t%zu", h.count) != 0)
        goto out;

    for (i = 0; i < h.count; i++) {
        size_t need = strlen(h.msgs[i].nick) +
                      strlen(h.msgs[i].timestamp) +
                      strlen(h.msgs[i].text) + 16;
        char *line = (char *)malloc(need);
        int n;
        if (line == NULL)
            goto out;
        n = snprintf(line, need, "HISTMSG\t%s\t%s\t%s",
                     h.msgs[i].nick, h.msgs[i].timestamp, h.msgs[i].text);
        if (n < 0 || (size_t)n >= need) {
            free(line);
            goto out;
        }
        if (cc_conn_send(&c->conn, line, (size_t)n) != 0) {
            free(line);
            goto out;
        }
        free(line);
    }

    if (send_fmt(&c->conn, "HISTEND") != 0)
        goto out;
    rc = 0;

out:
    cc_history_free(&h);
    memset(key, 0, sizeof(key));
    if (rc != 0)
        send_error(&c->conn, "Не удалось передать историю");
    return rc;
}

static void broadcast_line(const char *line, size_t len)
{
    client_t *c;

    pthread_mutex_lock(&g_clients_mu);
    for (c = g_clients; c != NULL; c = c->next) {
        if (c->joined)
            (void)cc_conn_send(&c->conn, line, len);
    }
    pthread_mutex_unlock(&g_clients_mu);
}

static void handle_chat_message(client_t *c, char *text)
{
    uint8_t key[CC_KEY_LEN];
    char ts[32];
    size_t need;
    char *line;
    int n;

    cc_sanitize_inline(text);
    cc_trim(text);

    if (text[0] == '\0')
        return;
    if (strlen(text) > CC_MAX_MESSAGE) {
        send_error(&c->conn, "Сообщение слишком длинное (максимум 2000 байт)");
        return;
    }

    cc_timestamp_now(ts);
    file_key(key);
    pthread_mutex_lock(&g_history_mu);
    n = cc_history_append(HISTORY_FILE, key, c->username, ts, text);
    pthread_mutex_unlock(&g_history_mu);
    memset(key, 0, sizeof(key));

    if (n != 0) {
        send_error(&c->conn, "Не удалось сохранить сообщение на сервере");
        return;
    }

    need = strlen(c->username) + strlen(ts) + strlen(text) + 8;
    line = (char *)malloc(need);
    if (line == NULL) {
        send_error(&c->conn, "Внутренняя ошибка сервера");
        return;
    }
    n = snprintf(line, need, "CHAT\t%s\t%s\t%s", c->username, ts, text);
    if (n > 0 && (size_t)n < need)
        broadcast_line(line, (size_t)n);
    free(line);
}

/* ------------------------------------------------------------------------- */
/* Обработка клиента                                                         */
/* ------------------------------------------------------------------------- */

static void remove_client(client_t *c)
{
    client_t **pp;

    pthread_mutex_lock(&g_clients_mu);
    pp = &g_clients;
    while (*pp != NULL) {
        if (*pp == c) {
            *pp = c->next;
            break;
        }
        pp = &(*pp)->next;
    }
    c->joined = 0;
    pthread_mutex_unlock(&g_clients_mu);
}

static int split_user_pass(char *args, char **user, char **pass)
{
    char *tab = strchr(args, '\t');

    if (tab == NULL)
        return -1;
    *tab = '\0';
    *user = args;
    *pass = tab + 1;
    if (strchr(*pass, '\t') != NULL)
        return -1;
    return 0;
}

static void *client_thread(void *arg)
{
    client_t *c = (client_t *)arg;
    char buf[8192];

    for (;;) {
        ssize_t n = cc_conn_recv(&c->conn, buf, sizeof(buf));
        if (n <= 0)
            break;

        if (strncmp(buf, "REGISTER\t", 9) == 0) {
            char *user, *pass;
            char err[256];
            if (c->authenticated) {
                send_error(&c->conn, "Вы уже вошли");
                continue;
            }
            if (split_user_pass(buf + 9, &user, &pass) != 0 ||
                !cc_username_valid(user) || !cc_password_valid(pass)) {
                send_error(&c->conn, "Некорректный ник или пароль "
                                     "(ник до 32 байт, пароль от 4 до 128)");
                continue;
            }
            if (register_account(user, pass, err, sizeof(err)) != 0) {
                send_error(&c->conn, err);
                continue;
            }
            snprintf(c->username, sizeof(c->username), "%.*s",
                     CC_MAX_NICK, user);
            c->authenticated = 1;
            if (send_fmt(&c->conn, "AUTHOK\t%s", c->username) != 0)
                break;
        } else if (strncmp(buf, "LOGIN\t", 6) == 0) {
            char *user, *pass;
            if (c->authenticated) {
                send_error(&c->conn, "Вы уже вошли");
                continue;
            }
            if (split_user_pass(buf + 6, &user, &pass) != 0 ||
                !cc_username_valid(user) || !cc_password_valid(pass)) {
                send_error(&c->conn, "Неверный ник или пароль");
                continue;
            }
            if (!login_account(user, pass)) {
                send_error(&c->conn, "Неверный ник или пароль");
                continue;
            }
            snprintf(c->username, sizeof(c->username), "%.*s",
                     CC_MAX_NICK, user);
            c->authenticated = 1;
            if (send_fmt(&c->conn, "AUTHOK\t%s", c->username) != 0)
                break;
        } else if (strcmp(buf, "HISTREQ") == 0) {
            if (!c->authenticated) {
                send_error(&c->conn, "Сначала войдите");
                continue;
            }
            if (send_history(c) != 0)
                break;
        } else if (strcmp(buf, "JOIN") == 0) {
            if (!c->authenticated) {
                send_error(&c->conn, "Сначала войдите");
                continue;
            }
            if (c->joined) {
                send_error(&c->conn, "Вы уже в чате");
                continue;
            }

            /*
             * Держим g_clients_mu и во время отправки READY: рассылка тоже
             * берёт этот мьютекс, поэтому READY гарантированно придёт раньше
             * первого сообщения из чата.
             */
            pthread_mutex_lock(&g_clients_mu);
            c->joined = 1;
            c->next = g_clients;
            g_clients = c;
            if (send_fmt(&c->conn, "READY") != 0) {
                pthread_mutex_unlock(&g_clients_mu);
                break;
            }
            pthread_mutex_unlock(&g_clients_mu);
        } else if (strncmp(buf, "MSG\t", 4) == 0) {
            if (!c->authenticated || !c->joined) {
                send_error(&c->conn, "Вы ещё не в чате");
                continue;
            }
            handle_chat_message(c, buf + 4);
        } else if (strcmp(buf, "QUIT") == 0) {
            break;
        } else if (strcmp(buf, "PING") == 0) {
            if (send_fmt(&c->conn, "PONG") != 0)
                break;
        } else {
            send_error(&c->conn, "Неизвестная команда");
        }
    }

    if (c->joined)
        remove_client(c);
    cc_conn_destroy(&c->conn);
    close(c->fd);
    free(c);
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* main                                                                       */
/* ------------------------------------------------------------------------- */

static int create_listen_socket(void)
{
    int fd;
    int yes = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SERVER_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "bind порта %d: %s\n", SERVER_PORT, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 32) != 0) {
        fprintf(stderr, "listen: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int main(void)
{
    int listen_fd;
    uint8_t fingerprint[32];
    char fp_hex[17];

    signal(SIGPIPE, SIG_IGN);

    if (ensure_data_files() != 0)
        return 1;

    listen_fd = create_listen_socket();
    if (listen_fd < 0)
        return 1;

    cc_sha256(SHARED_SECRET, strlen(SHARED_SECRET), fingerprint);
    cc_hex_encode(fingerprint, 8, fp_hex);

    printf("CCHAT server запущен\n");
    printf("Порт: %d\n", SERVER_PORT);
    printf("Данные: %s/\n", DATA_DIR);
    printf("Отпечаток ключа: %s (должен совпадать с клиентом)\n", fp_hex);
    printf("Ожидание подключений...\n");
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        client_t *c;
        pthread_t tid;
        int yes = 1;

        if (fd < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "accept: %s\n", strerror(errno));
            break;
        }

        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

        c = (client_t *)calloc(1, sizeof(*c));
        if (c == NULL) {
            close(fd);
            continue;
        }
        c->fd = fd;
        if (cc_conn_init(&c->conn, fd,
                         (const uint8_t *)SHARED_SECRET,
                         strlen(SHARED_SECRET), 1) != 0) {
            close(fd);
            free(c);
            continue;
        }

        if (pthread_create(&tid, NULL, client_thread, c) != 0) {
            cc_conn_destroy(&c->conn);
            close(fd);
            free(c);
            continue;
        }
        pthread_detach(tid);
    }

    close(listen_fd);
    return 0;
}
