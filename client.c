#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "crypto.h"
#include "history.h"
#include "net.h"
#include "util.h"

/* ========================================================================== */
/* Настройки клиента.                                                         */
/*                                                                            */
/* SHARED_SECRET должен быть ОДИНАКОВЫМ здесь и в server.c!                  */
/* DEFAULT_PORT используется при добавлении нового сервера.                  */
/* ========================================================================== */

#define DEFAULT_PORT  5555
#define SHARED_SECRET "CHANGE-ME-cchat-shared-secret-please-32-bytes-minimum"

#define CLIENT_DIR_NAME ".cchat"
#define MAX_SERVERS     256
#define MAX_SYNC_MSGS   200000

typedef struct {
    char name[CC_MAX_SERVER_NAME + 1];
    char host[256];
    int port;
} server_entry;

typedef struct {
    server_entry *items;
    size_t count;
    size_t cap;
} server_list;

static char g_client_dir[2048];
static char g_servers_file[3072];
static char g_history_dir[3072];

/* ------------------------------------------------------------------------- */
/* Ввод/вывод                                                                */
/* ------------------------------------------------------------------------- */

static int read_line(char *buf, size_t size)
{
    size_t len;

    if (fgets(buf, (int)size, stdin) == NULL)
        return 0;

    len = strlen(buf);
    if (len > 0 && buf[len - 1] != '\n' && !feof(stdin)) {
        int ch;
        /* Слишком длинная строка: выбрасываем остаток. */
        while ((ch = getchar()) != '\n' && ch != EOF)
            ;
    }
    cc_strip_newline(buf);
    return 1;
}

static int prompt_line(const char *prompt, char *buf, size_t size)
{
    printf("%s", prompt);
    fflush(stdout);
    return read_line(buf, size);
}

static int read_password(const char *prompt, char *buf, size_t size)
{
    struct termios oldt, newt;
    int tty = isatty(STDIN_FILENO);
    int ok;

    printf("%s", prompt);
    fflush(stdout);

    if (tty && tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) == 0) {
            ok = read_line(buf, size);
            (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
            printf("\n");
            return ok;
        }
    }
    ok = read_line(buf, size);
    if (tty)
        printf("\n");
    return ok;
}

static int parse_int(const char *s, int *out)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s)
        return -1;
    while (*end != '\0' && isspace((unsigned char)*end))
        end++;
    if (*end != '\0' || v < INT32_MIN || v > INT32_MAX)
        return -1;
    *out = (int)v;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Пути и список серверов                                                    */
/* ------------------------------------------------------------------------- */

static int init_paths(void)
{
    const char *home = getenv("HOME");
    int n;

    if (home == NULL || *home == '\0')
        home = ".";

    n = snprintf(g_client_dir, sizeof(g_client_dir), "%s/%s", home, CLIENT_DIR_NAME);
    if (n < 0 || (size_t)n >= sizeof(g_client_dir))
        return -1;
    n = snprintf(g_history_dir, sizeof(g_history_dir), "%s/history", g_client_dir);
    if (n < 0 || (size_t)n >= sizeof(g_history_dir))
        return -1;
    n = snprintf(g_servers_file, sizeof(g_servers_file), "%s/servers.tsv", g_client_dir);
    if (n < 0 || (size_t)n >= sizeof(g_servers_file))
        return -1;

    if (cc_mkdir_p(g_client_dir, 0700) != 0)
        return -1;
    if (cc_mkdir_p(g_history_dir, 0700) != 0)
        return -1;
    return 0;
}

static uint32_t fnv1a32(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s != '\0') {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

static void history_path(const server_entry *srv, char *out, size_t out_size)
{
    char slug[96];
    uint32_t hash;

    cc_slug(srv->name, slug, sizeof(slug));
    hash = fnv1a32(srv->name);
    snprintf(out, out_size, "%s/%s_%08x.enc", g_history_dir, slug,
             (unsigned)hash);
}

static void server_list_init(server_list *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static void server_list_free(server_list *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int server_list_add(server_list *list, const server_entry *srv)
{
    server_entry *p;

    if (list->count == list->cap) {
        size_t new_cap = list->cap == 0 ? 8 : list->cap * 2;
        if (new_cap > MAX_SERVERS)
            new_cap = MAX_SERVERS;
        if (new_cap <= list->cap)
            return -1;
        p = (server_entry *)realloc(list->items, new_cap * sizeof(*p));
        if (p == NULL)
            return -1;
        list->items = p;
        list->cap = new_cap;
    }
    list->items[list->count++] = *srv;
    return 0;
}

static int load_servers(server_list *list)
{
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;

    server_list_init(list);
    f = fopen(g_servers_file, "r");
    if (f == NULL)
        return errno == ENOENT ? 0 : -1;

    while ((n = getline(&line, &cap, f)) >= 0) {
        char *t1, *t2;
        int port;
        server_entry srv;
        (void)n;

        cc_strip_newline(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        t1 = strchr(line, '\t');
        if (t1 == NULL)
            continue;
        *t1 = '\0';
        t2 = strchr(t1 + 1, '\t');
        if (t2 == NULL)
            continue;
        *t2 = '\0';

        if (!cc_server_name_valid(line))
            continue;
        if (strlen(t1 + 1) == 0 || strlen(t1 + 1) >= sizeof(srv.host))
            continue;
        if (parse_int(t2 + 1, &port) != 0 || port <= 0 || port > 65535)
            continue;

        memset(&srv, 0, sizeof(srv));
        snprintf(srv.name, sizeof(srv.name), "%s", line);
        snprintf(srv.host, sizeof(srv.host), "%s", t1 + 1);
        srv.port = port;

        if (list->count >= MAX_SERVERS)
            break;
        if (server_list_add(list, &srv) != 0)
            break;
    }

    free(line);
    fclose(f);
    return 0;
}

static int save_servers(const server_list *list)
{
    char tmp[4096];
    FILE *f;
    size_t i;
    int n;

    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", g_servers_file, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return -1;

    f = fopen(tmp, "w");
    if (f == NULL)
        return -1;

    for (i = 0; i < list->count; i++) {
        if (fprintf(f, "%s\t%s\t%d\n", list->items[i].name,
                    list->items[i].host, list->items[i].port) < 0) {
            fclose(f);
            unlink(tmp);
            return -1;
        }
    }
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    if (fclose(f) != 0) {
        unlink(tmp);
        return -1;
    }
    (void)chmod(tmp, 0600);
    if (rename(tmp, g_servers_file) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int find_server_by_name(const server_list *list, const char *name)
{
    size_t i;
    for (i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

static void add_server_flow(server_list *list)
{
    server_entry srv;
    char host[256], name[CC_MAX_SERVER_NAME + 1], portbuf[32];
    int port = DEFAULT_PORT;

    memset(&srv, 0, sizeof(srv));

    printf("\n--- Добавление сервера ---\n");
    if (!prompt_line("IP или домен сервера: ", host, sizeof(host)))
        return;
    cc_trim(host);
    if (host[0] == '\0' || strlen(host) >= sizeof(srv.host)) {
        printf("Некорректный адрес.\n");
        return;
    }

    if (!prompt_line("Название сервера: ", name, sizeof(name)))
        return;
    cc_trim(name);
    if (!cc_server_name_valid(name)) {
        printf("Некорректное название (до %d байт, без : / \\).\n",
               CC_MAX_SERVER_NAME);
        return;
    }
    if (find_server_by_name(list, name) >= 0) {
        printf("Сервер с таким названием уже добавлен.\n");
        return;
    }

    printf("Порт [%d]: ", DEFAULT_PORT);
    fflush(stdout);
    if (!read_line(portbuf, sizeof(portbuf)))
        return;
    cc_trim(portbuf);
    if (portbuf[0] != '\0') {
        if (parse_int(portbuf, &port) != 0 || port <= 0 || port > 65535) {
            printf("Некорректный порт.\n");
            return;
        }
    }

    snprintf(srv.name, sizeof(srv.name), "%s", name);
    snprintf(srv.host, sizeof(srv.host), "%s", host);
    srv.port = port;

    if (list->count >= MAX_SERVERS) {
        printf("Достигнут лимит серверов (%d).\n", MAX_SERVERS);
        return;
    }
    if (server_list_add(list, &srv) != 0 || save_servers(list) != 0) {
        printf("Не удалось сохранить список серверов.\n");
        return;
    }
    printf("Сервер «%s» добавлен: %s:%d\n", srv.name, srv.host, srv.port);
}

/* ------------------------------------------------------------------------- */
/* Сеть                                                                      */
/* ------------------------------------------------------------------------- */

static int connect_to_server(const server_entry *srv)
{
    struct addrinfo hints, *res, *rp;
    char portbuf[16];
    int fd = -1;

    snprintf(portbuf, sizeof(portbuf), "%d", srv->port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(srv->host, portbuf, &hints, &res) != 0) {
        printf("Не удалось разрешить адрес %s.\n", srv->host);
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        printf("Не удалось подключиться к %s:%d: %s\n",
               srv->host, srv->port, strerror(errno));
        return -1;
    }

    {
        int yes = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    }
    return fd;
}

static void print_err_packet(const char *packet)
{
    if (strncmp(packet, "ERR\t", 4) == 0)
        printf("Ошибка сервера: %s\n", packet + 4);
    else
        printf("Неожиданный ответ сервера: %s\n", packet);
}

/*
 * Возвращает 0 и инициализированные conn/username при успехе.
 * fd остаётся открытым и должен быть закрыт вызывающим.
 */
static int authenticate_and_sync(const server_entry *srv, int do_register,
                                 cc_conn_t *conn, char *username,
                                 size_t username_size)
{
    char nick[CC_MAX_NICK + 1];
    char pass[CC_MAX_PASSWORD + 1];
    char pass2[CC_MAX_PASSWORD + 1];
    char line[512];
    char packet[8192];
    char hist_path[4096];
    uint8_t key[CC_KEY_LEN];
    cc_history hist;
    unsigned long long count = 0;
    unsigned long long i;
    ssize_t n;
    int fd = -1;
    int rc = -1;

    if (!prompt_line("Никнейм: ", nick, sizeof(nick)))
        return -1;
    cc_trim(nick);
    if (!cc_username_valid(nick)) {
        printf("Ник: до %d байт, без пробелов и символов : / \\\n", CC_MAX_NICK);
        return -1;
    }

    if (!read_password("Пароль: ", pass, sizeof(pass)))
        return -1;
    if (!cc_password_valid(pass)) {
        printf("Пароль должен быть от 4 до %d символов и без управляющих символов.\n",
               CC_MAX_PASSWORD);
        return -1;
    }

    if (do_register) {
        if (!read_password("Повторите пароль: ", pass2, sizeof(pass2)))
            return -1;
        if (strcmp(pass, pass2) != 0) {
            printf("Пароли не совпадают.\n");
            return -1;
        }
    }

    printf("Подключение к %s:%d...\n", srv->host, srv->port);
    fd = connect_to_server(srv);
    if (fd < 0)
        goto out;

    if (cc_conn_init(conn, fd, (const uint8_t *)SHARED_SECRET,
                     strlen(SHARED_SECRET), 0) != 0) {
        printf("Не удалось инициализировать соединение.\n");
        goto out;
    }

    if (do_register)
        snprintf(line, sizeof(line), "REGISTER\t%s\t%s", nick, pass);
    else
        snprintf(line, sizeof(line), "LOGIN\t%s\t%s", nick, pass);

    if (cc_conn_send(conn, line, strlen(line)) != 0) {
        printf("Не удалось отправить запрос серверу.\n");
        goto out_conn;
    }

    n = cc_conn_recv(conn, packet, sizeof(packet));
    if (n <= 0) {
        printf("Сервер закрыл соединение во время входа.\n");
        goto out_conn;
    }
    if (strncmp(packet, "AUTHOK\t", 7) != 0) {
        print_err_packet(packet);
        goto out_conn;
    }
    snprintf(username, username_size, "%.*s", CC_MAX_NICK, packet + 7);
    printf("%s как %s.\n", do_register ? "Аккаунт создан, вход выполнен" :
                                         "Вход выполнен", username);

    /* Скачиваем полную историю сервера и сохраняем локальную копию. */
    if (cc_conn_send(conn, "HISTREQ", 7) != 0) {
        printf("Не удалось запросить историю.\n");
        goto out_conn;
    }

    n = cc_conn_recv(conn, packet, sizeof(packet));
    if (n <= 0 || strncmp(packet, "HISTCOUNT\t", 10) != 0) {
        if (n > 0)
            print_err_packet(packet);
        printf("Сервер не передал историю.\n");
        goto out_conn;
    }

    errno = 0;
    count = strtoull(packet + 10, NULL, 10);
    if (errno != 0 || count > MAX_SYNC_MSGS) {
        printf("История слишком большая для синхронизации (лимит %d сообщений).\n",
               MAX_SYNC_MSGS);
        goto out_conn;
    }

    cc_history_init(&hist);
    for (i = 0; i < count; i++) {
        char *t1, *t2;
        n = cc_conn_recv(conn, packet, sizeof(packet));
        if (n <= 0 || strncmp(packet, "HISTMSG\t", 8) != 0) {
            printf("Ошибка синхронизации истории.\n");
            goto out_hist;
        }
        t1 = strchr(packet + 8, '\t');
        if (t1 == NULL) {
            printf("Ошибка формата истории.\n");
            goto out_hist;
        }
        *t1 = '\0';
        t2 = strchr(t1 + 1, '\t');
        if (t2 == NULL) {
            printf("Ошибка формата истории.\n");
            goto out_hist;
        }
        *t2 = '\0';

        if (cc_history_add(&hist, packet + 8, t1 + 1, t2 + 1) != 0) {
            printf("Не хватает памяти для истории.\n");
            goto out_hist;
        }
    }

    n = cc_conn_recv(conn, packet, sizeof(packet));
    if (n <= 0 || strcmp(packet, "HISTEND") != 0) {
        printf("Сервер не завершил передачу истории.\n");
        goto out_hist;
    }

    cc_derive_key((const uint8_t *)SHARED_SECRET, strlen(SHARED_SECRET),
                  "cchat-file-v1", key);
    history_path(srv, hist_path, sizeof(hist_path));
    if (cc_history_save(hist_path, key, &hist) != 0)
        printf("Предупреждение: не удалось сохранить локальную историю.\n");
    cc_history_free(&hist);
    memset(key, 0, sizeof(key));

    if (cc_conn_send(conn, "JOIN", 4) != 0) {
        printf("Не удалось войти в чат.\n");
        goto out_conn;
    }
    n = cc_conn_recv(conn, packet, sizeof(packet));
    if (n <= 0 || strcmp(packet, "READY") != 0) {
        if (n > 0)
            print_err_packet(packet);
        else
            printf("Сервер не подтвердил вход в чат.\n");
        goto out_conn;
    }

    rc = 0;
    goto out;

out_hist:
    cc_history_free(&hist);
out_conn:
    cc_conn_destroy(conn);
out:
    if (fd >= 0 && rc != 0)
        close(fd);
    memset(pass, 0, sizeof(pass));
    memset(pass2, 0, sizeof(pass2));
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Чат                                                                       */
/* ------------------------------------------------------------------------- */

static void chat_loop(int fd, cc_conn_t *conn, const server_entry *srv,
                      const char *username)
{
    char hist_path[4096];
    uint8_t key[CC_KEY_LEN];
    char *input = NULL;
    size_t input_cap = 0;
    int prompt_shown = 0;
    int tty = isatty(STDIN_FILENO);

    history_path(srv, hist_path, sizeof(hist_path));
    cc_derive_key((const uint8_t *)SHARED_SECRET, strlen(SHARED_SECRET),
                  "cchat-file-v1", key);

    printf("\n=== ЧАТ: %s (%s:%d) ===\n", srv->name, srv->host, srv->port);
    printf("Вы вошли как %s. /quit — выход, /help — помощь.\n\n", username);

    for (;;) {
        struct pollfd pfd[2];
        int pr;

        if (!prompt_shown) {
            printf("> ");
            fflush(stdout);
            prompt_shown = 1;
        }

        pfd[0].fd = fd;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        pfd[1].fd = STDIN_FILENO;
        pfd[1].events = POLLIN;
        pfd[1].revents = 0;

        pr = poll(pfd, 2, -1);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            printf("\nОшибка poll: %s\n", strerror(errno));
            break;
        }

        if ((pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            char packet[8192];
            ssize_t n = cc_conn_recv(conn, packet, sizeof(packet));

            if (n <= 0) {
                if (tty)
                    printf("\r\033[K");
                printf("Соединение с сервером закрыто.\n");
                break;
            }

            if (tty && prompt_shown)
                printf("\r\033[K");
            prompt_shown = 0;

            if (strncmp(packet, "CHAT\t", 5) == 0) {
                char *t1 = strchr(packet + 5, '\t');
                if (t1 != NULL) {
                    char *t2;
                    *t1 = '\0';
                    t2 = strchr(t1 + 1, '\t');
                    if (t2 != NULL) {
                        const char *nick = packet + 5;
                        const char *ts = t1 + 1;
                        const char *text = t2 + 1;
                        *t2 = '\0';
                        printf("[%s] %s: %s\n", ts, nick, text);
                        if (cc_history_append(hist_path, key, nick, ts, text) != 0)
                            printf("(не удалось сохранить сообщение в локальную историю)\n");
                    }
                }
            } else if (strncmp(packet, "ERR\t", 4) == 0) {
                printf("Ошибка сервера: %s\n", packet + 4);
            } else if (strcmp(packet, "PONG") != 0) {
                printf("%s\n", packet);
            }
        }

        if ((pfd[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            ssize_t len = getline(&input, &input_cap, stdin);
            prompt_shown = 0;

            if (len < 0) {
                (void)cc_conn_send(conn, "QUIT", 4);
                break;
            }
            cc_strip_newline(input);
            cc_sanitize_inline(input);
            cc_trim(input);

            if (input[0] == '\0')
                continue;
            if (strcmp(input, "/quit") == 0 || strcmp(input, "/exit") == 0) {
                (void)cc_conn_send(conn, "QUIT", 4);
                break;
            }
            if (strcmp(input, "/help") == 0) {
                printf("Введите сообщение и нажмите Enter. /quit — выход.\n");
                continue;
            }
            if (strlen(input) > CC_MAX_MESSAGE) {
                printf("Сообщение длиннее %d байт и не отправлено.\n",
                       CC_MAX_MESSAGE);
                continue;
            }

            {
                size_t need = strlen(input) + 5;
                char *msg = (char *)malloc(need);
                if (msg == NULL) {
                    printf("Не хватает памяти.\n");
                    continue;
                }
                snprintf(msg, need, "MSG\t%s", input);
                if (cc_conn_send(conn, msg, strlen(msg)) != 0) {
                    free(msg);
                    printf("Не удалось отправить сообщение.\n");
                    break;
                }
                free(msg);
            }
        }
    }

    free(input);
    memset(key, 0, sizeof(key));
}

/* ------------------------------------------------------------------------- */
/* Просмотр истории                                                          */
/* ------------------------------------------------------------------------- */

static void print_history_chunk(const cc_history *h, size_t chunk)
{
    size_t chunks = (h->count + CC_PAGE_SIZE - 1) / CC_PAGE_SIZE;
    size_t start = chunk * CC_PAGE_SIZE;
    size_t end = start + CC_PAGE_SIZE;
    size_t i;

    if (end > h->count)
        end = h->count;

    printf("\n========== Кусок %zu из %zu ==========\n", chunk + 1, chunks);
    for (i = start; i < end; i++) {
        printf("[%s] %s: %s\n", h->msgs[i].timestamp,
               h->msgs[i].nick, h->msgs[i].text);
    }
    printf("========== конец куска %zu/%zu ==========\n", chunk + 1, chunks);
}

static void show_history_for_server(const server_entry *srv)
{
    char path[4096];
    uint8_t key[CC_KEY_LEN];
    cc_history h;
    size_t chunks;
    size_t current = 0;
    char input[64];

    history_path(srv, path, sizeof(path));
    cc_derive_key((const uint8_t *)SHARED_SECRET, strlen(SHARED_SECRET),
                  "cchat-file-v1", key);

    if (cc_history_load(path, key, &h) != 0) {
        printf("Не удалось прочитать или расшифровать историю: %s\n", path);
        memset(key, 0, sizeof(key));
        return;
    }
    memset(key, 0, sizeof(key));

    printf("\n=== ИСТОРИЯ: %s (%s:%d) ===\n", srv->name, srv->host, srv->port);
    printf("Файл: %s\n", path);
    printf("Сообщений: %zu. Доступно кусков: ", h.count);

    chunks = (h.count + CC_PAGE_SIZE - 1) / CC_PAGE_SIZE;
    if (chunks == 0) {
        printf("0 (история пуста)\n");
        cc_history_free(&h);
        return;
    }
    printf("%zu (по %d сообщений, куски 1..%zu)\n",
           chunks, CC_PAGE_SIZE, chunks);
    printf("Доступные куски: ");
    {
        size_t i;
        for (i = 1; i <= chunks; i++)
            printf("%zu%s", i, i == chunks ? "" : ", ");
        printf("\n");
    }

    for (;;) {
        int num;

        print_history_chunk(&h, current);
        printf("Кусок %zu/%zu. Введите номер куска (1..%zu, 0 — выход): ",
               current + 1, chunks, chunks);
        fflush(stdout);

        if (!read_line(input, sizeof(input))) {
            printf("\n");
            break;
        }
        cc_trim(input);
        if (input[0] == '\0')
            continue;
        if (strcmp(input, "q") == 0 || strcmp(input, "quit") == 0)
            break;
        if (parse_int(input, &num) != 0 || num < 0 || (size_t)num > chunks) {
            printf("Нет такого куска. Введите число от 1 до %zu.\n", chunks);
            continue;
        }
        if (num == 0)
            break;
        current = (size_t)num - 1;
    }

    cc_history_free(&h);
}

static int history_flow(const server_list *list)
{
    char input[64];
    int num;

    if (list->count == 0) {
        printf("Сначала добавьте хотя бы один сервер (пункт 0).\n");
        return 0;
    }

    printf("\n--- Просмотр истории ---\n");
    {
        size_t i;
        for (i = 0; i < list->count; i++) {
            printf("  %zu) %s (%s:%d)\n", i + 1,
                   list->items[i].name, list->items[i].host,
                   list->items[i].port);
        }
    }
    if (!prompt_line("Введите номер сервера (0 — назад): ", input, sizeof(input)))
        return 0;
    cc_trim(input);
    if (parse_int(input, &num) != 0 || num < 0 ||
        (size_t)num > list->count) {
        printf("Некорректный номер сервера.\n");
        return 0;
    }
    if (num == 0)
        return 0;

    show_history_for_server(&list->items[num - 1]);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Меню                                                                      */
/* ------------------------------------------------------------------------- */

static int server_menu(const server_list *list, size_t index)
{
    const server_entry *srv = &list->items[index];
    char input[64];

    for (;;) {
        int num;

        printf("\n=== %s (%s:%d) ===\n", srv->name, srv->host, srv->port);
        printf("  1) Войти в чат\n");
        printf("  2) Присоединиться (создать аккаунт)\n");
        printf("  3) Прочитать историю этого сервера\n");
        printf("  0) Назад\n");
        printf("Выбор: ");
        fflush(stdout);

        if (!read_line(input, sizeof(input)))
            return 0;
        cc_trim(input);

        if (parse_int(input, &num) != 0) {
            printf("Введите число.\n");
            continue;
        }
        if (num == 0)
            return 0;
        if (num == 3) {
            show_history_for_server(srv);
            continue;
        }
        if (num == 1 || num == 2) {
            cc_conn_t conn;
            char username[CC_MAX_NICK + 1];
            int fd;

            if (authenticate_and_sync(srv, num == 2, &conn,
                                      username, sizeof(username)) != 0) {
                continue;
            }
            fd = conn.fd;
            chat_loop(fd, &conn, srv, username);
            cc_conn_destroy(&conn);
            close(fd);
            continue;
        }
        printf("Неверный выбор.\n");
    }
}

static void main_menu(server_list *list)
{
    char input[128];

    for (;;) {
        size_t i;
        int num;

        printf("\n========== CCHAT ==========\n");
        printf("  0) Добавить сервер по IP\n");
        for (i = 0; i < list->count; i++) {
            printf("  %zu) %s (%s:%d)\n", i + 1,
                   list->items[i].name, list->items[i].host,
                   list->items[i].port);
        }
        printf("  h) Прочитать историю чата\n");
        printf("  q) Выход\n");
        printf("Выбор: ");
        fflush(stdout);

        if (!read_line(input, sizeof(input)))
            return;
        cc_trim(input);

        if (strcmp(input, "q") == 0 || strcmp(input, "quit") == 0)
            return;
        if (strcmp(input, "h") == 0 || strcmp(input, "H") == 0 ||
            strcmp(input, "r") == 0) {
            history_flow(list);
            continue;
        }
        if (parse_int(input, &num) != 0) {
            printf("Введите номер сервера, h или q.\n");
            continue;
        }
        if (num == 0) {
            add_server_flow(list);
            continue;
        }
        if (num < 1 || (size_t)num > list->count) {
            printf("Нет сервера с таким номером.\n");
            continue;
        }
        server_menu(list, (size_t)num - 1);
    }
}

static void print_usage(const char *argv0)
{
    printf("Использование:\n");
    printf("  %s            — обычный запуск (меню)\n", argv0);
    printf("  %s --history  — сразу просмотр истории (удобно для второго терминала)\n",
           argv0);
    printf("  %s --help     — эта справка\n", argv0);
}

int main(int argc, char **argv)
{
    server_list list;
    int history_only = 0;

    signal(SIGPIPE, SIG_IGN);

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--help") != 0 &&
                     strcmp(argv[1], "--history") != 0)) {
        print_usage(argv[0]);
        return 1;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--history") == 0)
        history_only = 1;

    if (init_paths() != 0) {
        fprintf(stderr, "Не удалось создать каталог %s\n", g_client_dir);
        return 1;
    }
    if (load_servers(&list) != 0) {
        fprintf(stderr, "Не удалось прочитать %s\n", g_servers_file);
        return 1;
    }

    if (history_only)
        history_flow(&list);
    else
        main_menu(&list);

    server_list_free(&list);
    return 0;
}
