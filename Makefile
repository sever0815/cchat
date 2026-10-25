CC      ?= gcc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS += -D_POSIX_C_SOURCE=200809L
LDLIBS  += -pthread

COMMON = crypto.c net.c history.c util.c
HEADERS = crypto.h net.h history.h util.h

.PHONY: all clean

all: cchat-server cchat

cchat-server: server.c $(COMMON) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ server.c $(COMMON) $(LDLIBS)

cchat: client.c $(COMMON) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ client.c $(COMMON) $(LDLIBS)

clean:
	rm -f cchat-server cchat
