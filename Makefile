# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers

CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -pthread -fPIC -Isrc
LDFLAGS ?= -lcrypto

SRCS = src/causal_daemon.c src/causal_daemon.h

all: causal_daemon libcausal_slash.so sdk/libbloodhound.so

# Shared Bloodhound watchtower for Python FFI (e2e_full_stack_live.py / sdk/bloodhound.py).
# Compiled WITHOUT BLOODHOUND_MAIN; exposes bloodhound_new/inspect_packet + csls core.
sdk/libbloodhound.so: src/schnorr_bloodhound.c src/causal_daemon.c src/causal_daemon.h src/schnorr_bloodhound.h
	$(CC) $(CFLAGS) -DCSLS_NO_MAIN -shared src/schnorr_bloodhound.c src/causal_daemon.c $(LDFLAGS) -o sdk/libbloodhound.so

causal_daemon: $(SRCS)
	$(CC) $(CFLAGS) src/causal_daemon.c $(LDFLAGS) -o causal_daemon

libcausal_slash.so: $(SRCS)
	$(CC) $(CFLAGS) -shared src/causal_daemon.c $(LDFLAGS) -o sdk/libcausal_slash.so

test: causal_daemon
	./causal_daemon --all
	rm -f causal_daemon

demo: libcausal_slash.so
	python3 examples/quickstart_agent.py

test-asan:
	$(CC) -O3 -fsanitize=address,undefined -g -Wall -Wextra -pthread -Isrc src/causal_daemon.c $(LDFLAGS) -o causal_daemon_asan
	./causal_daemon_asan --all
	rm -f causal_daemon_asan

test-concurrency:
	$(CC) $(CFLAGS) test/c/test_concurrency.c $(LDFLAGS) -o test_concurrency
	./test_concurrency
	rm -f test_concurrency

test-agent-concurrency:
	$(CC) $(CFLAGS) -DCSLS_NO_MAIN test/c/test_agent_concurrency.c src/causal_daemon.c $(LDFLAGS) -o test_agent_concurrency
	./test_agent_concurrency
	rm -f test_agent_concurrency

test-bloat:
	$(CC) $(CFLAGS) test/c/test_state_bloat.c $(LDFLAGS) -o test_state_bloat
	./test_state_bloat
	rm -f test_state_bloat

test-redteam:
	$(CC) -fsanitize=address,undefined -g -Wall -Wextra -pthread -DCSLS_NO_MAIN -Isrc test/c/test_redteam_exploit.c src/causal_daemon.c $(LDFLAGS) -o test_redteam_exploit
	./test_redteam_exploit
	rm -f test_redteam_exploit

test-competitor:
	$(CC) -fsanitize=address,undefined -g -Wall -Wextra -pthread -DCSLS_NO_MAIN -Isrc test/c/test_competitor_griefing.c src/causal_daemon.c $(LDFLAGS) -o test_competitor_griefing
	./test_competitor_griefing
	rm -f test_competitor_griefing

test-audit:
	$(CC) -fsanitize=address,undefined -g -Wall -Wextra -pthread -DCSLS_NO_MAIN -Isrc test/c/test_reliability_audit.c src/causal_daemon.c $(LDFLAGS) -o test_reliability_audit
	./test_reliability_audit
	rm -f test_reliability_audit

test-bloodhound:
	$(CC) -fsanitize=address,undefined -g -Wall -Wextra -pthread -DCSLS_NO_MAIN -Isrc test/c/test_schnorr_bloodhound.c src/schnorr_bloodhound.c src/causal_daemon.c $(LDFLAGS) -o test_schnorr_bloodhound
	./test_schnorr_bloodhound
	rm -f test_schnorr_bloodhound

# Strict bare-metal gate: enforces the 35ns interception invariant (no sanitizer).
test-bloodhound-strict:
	$(CC) -O3 -Wall -Wextra -pthread -DBLOODHOUND_PERF_STRICT -DCSLS_NO_MAIN -Isrc test/c/test_schnorr_bloodhound.c src/schnorr_bloodhound.c src/causal_daemon.c $(LDFLAGS) -o test_schnorr_bloodhound_strict
	./test_schnorr_bloodhound_strict
	rm -f test_schnorr_bloodhound_strict

test-30k-swarm:
	$(CC) $(CFLAGS) -DCSLS_NO_MAIN test/c/test_30k_adversarial_swarm.c src/causal_daemon.c $(LDFLAGS) -o test_30k_adversarial_swarm
	./test_30k_adversarial_swarm
	rm -f test_30k_adversarial_swarm


bloodhound_daemon:
	$(CC) $(CFLAGS) -DCSLS_NO_MAIN -DBLOODHOUND_MAIN src/schnorr_bloodhound.c src/causal_daemon.c $(LDFLAGS) -o bloodhound_daemon

clean:
	rm -f causal_daemon sdk/libcausal_slash.so libcausal_slash.so causal_daemon_asan test_concurrency test_state_bloat test_competitor_griefing test_redteam_exploit test_reliability_audit test_schnorr_bloodhound *.o

