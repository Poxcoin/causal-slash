# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Causal-Slash Protocol Developers

CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -pthread -fPIC
LDFLAGS ?= -lcrypto

all: causal_daemon libcausal_slash.so

causal_daemon: causal_daemon.c causal_daemon.h
	$(CC) $(CFLAGS) causal_daemon.c $(LDFLAGS) -o causal_daemon

libcausal_slash.so: causal_daemon.c causal_daemon.h
	$(CC) $(CFLAGS) -shared causal_daemon.c $(LDFLAGS) -o libcausal_slash.so

test: causal_daemon
	./causal_daemon --all

test-asan:
	$(CC) -O3 -fsanitize=address,undefined -g -Wall -Wextra -pthread causal_daemon.c $(LDFLAGS) -o causal_daemon_asan
	./causal_daemon_asan --all
	rm -f causal_daemon_asan

clean:
	rm -f causal_daemon libcausal_slash.so causal_daemon_asan *.o
