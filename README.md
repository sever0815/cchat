# CCHAT — консольный мессенджер на C (итог)

## Что сделано

### Архитектура
- **Сервер** (`server.c`) — потоковый сервер на pthread,.listen on TCP, хранилище аккаунтов в `data/users.db`, зашифрованная история в `data/chat.log.enc`.
- **Клиент** (`client.c`) — интерактивный CLI с Poll/Threaded receiver, сохранение локальной истории в `~/.cchat/history/`.
- **Криптография** (`crypto.c`) — own SHA-256, HMAC-SHA256, PBKDF2, ChaCha20 (RFC 8439), encrypt-then-MAC.
- **Интерфейс** (`util.c`, `util.h`) — утилиты: trim, slug, PBKDF2, случайные байты.
- **История** (`history.c`, `history.h`) — зашифрованный append-only файл, куски по 100 сообщений.
- **Сеть** (`net.c`, `net.h`) — протокол: header (4byte length) + ChaCha20 blob (nonce+cipher+tag), constant-time проверка MAC.

### Ключевые возможности
1. **Аккаунты** — регистрация (`REGISTER nickname password`) и вход (`LOGIN nickname password`), пароли хешируются PBKDF2-HMAC-SHA256 (80000 итераций).
2. **Шифрование трафика** — все сообщения ChaCha20+HMAC, ключиderived от `SHARED_SECRET` (общий для server.c и client.c).
3. **История чата** — сохраняется на сервере (`data/chat.log.enc`) и у каждого клиента (`~/.cchat/history/<name>_<hash>.enc`).
4. **Просмотр истории без входа** — `./cchat --history` или пункт меню `3`, история разделяна на куски по 100 msg, ввод номера куска.
5. **Фоновый режим сервера** — `./cchat-server --daemon` или `./cchat-server -d`, сервер уходит в background, терминал освобождается.
6. **Меню выбора сервера** — `0` добавить сервер по IP+название, `1..N` выбрать, `h` прочитать историю, `q` выход.

### Как запустить

```sh
# 1. Соберите
make

# 2. Отредактируйте KEY в обоих .c файлах (должно совпадать!)
#   #define SHARED_SECRET "ваш-ключ-минимум-32-байта"
#   #define SERVER_PORT 8080  (server.c)
#   #define DEFAULT_PORT 8080 (client.c)

# 3. Запустите сервер (вариант а: в foreground)
./cchat-server

#    или б: в фоновом режиме (терминал освобождается)
./cchat-server --daemon
#    или в короче:
./cchat-server -d

# 3. Запустите клиент (в другом терминале)
./cchat

# 4. В клиенте: 0 — добавить сервер, 1..N — выбрать,
#    1 — вход, 2 — регистрация, h — история, /quit — выход.

# 5. Чтобы остановить фоновый сервер:
pkill -x cchat-server
```

### Решение проблемы "не вижу сообщения друга"
Была добавлена отдельная нить receiver в клиенте (`chat_receiver_thread`). Это гарантирует, что входящие сообщения обрабатываются параллельно с вводом с клавиатуры, а вывод через `chat_emit` корректно управляет приглашением `> ` в терминале. Теперь обе стороны видят сообщения друг друга сразу.

### Структура файлов
```
cchat/                              — проект
├─ server.c                         — сервер
├─ client.c                         — клиент
├─ crypto.c / crypto.h              — криптография
├─ history.c / history.h            — зашифрованная история
├─ net.c / net.h                    — сеть и протокол
├─ util.c / util.h                  — утилиты
├─ Makefile                         — сборка
├─ .gitignore
├─ README.md                        — документация
└─ data/                            — создается сервером при первом запуске
    ├─ users.db                     — аккаунты
    └─ chat.log.enc                 — общая история
```

### Требуемые знания
- Linux, POSIX сockets, pthread
- gcc, make
- Базовый криптography (ChaCha20, HMAC)

Все собрано и протестировано: регистрация/вход, bidirectional chat, история с кусками по 100, daemon-режим сервера.