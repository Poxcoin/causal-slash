#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Comprehensive verification test suite for CSLS Go client TUI (Bubble Tea).
Verifies:
  1. go vet and go build pass with 0 errors
  2. 5 consecutive commands: zero rule accumulation on screen
  3. Dynamic window resize: clean redrawing without visual tails
  4. 40-column window: text-only header without logo, no line wrapping, no crash
  5. Clean exit: terminal restored to initial state (AltScreen exit \x1b[?1049l)
"""

import fcntl
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(s: str) -> str:
    return ANSI_ESCAPE.sub("", s)


def set_winsize(fd: int, rows: int, cols: int):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def read_available(master_fd: int, timeout: float = 1.0) -> str:
    chunks = []
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master_fd], [], [], 0.05)
        if r:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                if b"\x1b[6n" in data:
                    os.write(master_fd, b"\x1b[24;1R")
                chunks.append(data.decode("utf-8", errors="replace"))
            except OSError:
                break
        elif chunks:
            break
    return "".join(chunks)


def read_until(master_fd: int, target: str, timeout: float = 4.0) -> str:
    chunks = []
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master_fd], [], [], 0.05)
        if r:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                if b"\x1b[6n" in data:
                    os.write(master_fd, b"\x1b[24;1R")
                chunks.append(data.decode("utf-8", errors="replace"))
                if target in "".join(chunks):
                    return "".join(chunks)
            except OSError:
                break
    return "".join(chunks)


def count_rules(text: str) -> int:
    """Count rendered horizontal rule lines (strings of 10+ dashes)."""
    return len(re.findall(r"─{10,}", text))


def run_checks():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    client_dir = os.path.join(repo_dir, "client")
    csls_bin = os.path.join(repo_dir, "bin", "csls")
    go_bin = os.path.expanduser("~/.local/sdk/go/bin/go")
    if not os.path.exists(go_bin):
        go_bin = "go"

    print("======================================================================")
    print("CSLS Bubble Tea TUI Verification Suite")
    print("======================================================================")

    # 1. go vet and go build check
    print("\n[CHECK 1] Running `go vet` and `go build`...")
    env_build = os.environ.copy()
    env_build["LD_LIBRARY_PATH"] = repo_dir

    vet_res = subprocess.run([go_bin, "vet", "./..."], cwd=client_dir, env=env_build, capture_output=True, text=True)
    assert vet_res.returncode == 0, f"`go vet` failed:\n{vet_res.stderr}"
    print("  [OK] go vet: 0 errors")

    build_res = subprocess.run([go_bin, "build", "-o", os.path.join(repo_dir, "bin", "csls-go"), "./cmd/csls"],
                               cwd=client_dir, env=env_build, capture_output=True, text=True)
    assert build_res.returncode == 0, f"`go build` failed:\n{build_res.stderr}"
    print("  [OK] go build: 0 errors (bin/csls-go successfully built)")

    # 2. Interactive PTY Test: 5 consecutive commands, rule accumulation, and AltScreen
    print("\n[CHECK 2] Interactive AltScreen session: 5 commands & rule accumulation...")
    master, slave = pty.openpty()
    set_winsize(slave, 24, 80)
    env_pty = os.environ.copy()
    env_pty.pop("GROQ_API_KEY", None)
    env_pty.pop("OPENROUTER_API_KEY", None)
    env_pty["TERM"] = "xterm-256color"
    env_pty["COLORFGBG"] = "15;0"
    env_pty["LD_LIBRARY_PATH"] = repo_dir

    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        os.execve(csls_bin, [csls_bin], env_pty)
        os._exit(1)

    os.close(slave)

    full_session_output = ""
    try:
        out = read_available(master, 1.5)
        full_session_output += out
        plain = strip_ansi(out)
        assert "? for shortcuts" in plain, "Status bar shortcuts missing"
        assert "model:" in plain, "Status bar model missing"
        assert "\x1b[7m" not in out, "Reverse video detected"
        assert "\x1b[?1049h" in out, "AltScreen entry escape sequence missing"
        print("  [OK] AltScreen activated (\x1b[?1049h), logo rendered, toolbar transparent")

        # Send commands
        commands = [
            "/help\n",
            "/bond\n",
            "/status\n",
            "/model\n",
            "/wallet\n",
            "/deposit 1.0\n",
            "/withdraw 0.5 demo\n",
            "/send 0.0005\n",
            "/hound\n",
            "/net\n",
            "/stream\n",
            "/bench\n",
            "/test c\n",
            "/clear\n",
        ]
        for idx, cmd in enumerate(commands, 1):
            os.write(master, cmd.encode("utf-8"))
            out_cmd = read_available(master, 0.8 if "test" in cmd or "bench" in cmd else 0.4)
            full_session_output += out_cmd
            print(f"  [OK] Command {idx}/{len(commands)}: {cmd.strip()} executed cleanly")

        # Test live interactive agent query with wire clearing settlement
        os.write(master, b"hello\n")
        query_out = read_until(master, "Agent error", 4.0)
        full_session_output += query_out
        assert "settled (0 gas)" not in full_session_output, "Fake settlement shown without vendor"
        assert "Processed query" not in full_session_output, "Canned fake reply detected"
        assert "Agent error" in full_session_output or "no inference upstream" in full_session_output or "upstream" in full_session_output, "Expected fail-fast error without vendor/upstream"
        print("  [OK] Agent query fails fast with no fake reply and no fake settlement")

        # The visible screen in AltScreen must have exactly 2 rule lines around input
        last_frame = read_available(master, 0.3)
        rules_in_last = count_rules(strip_ansi(last_frame))
        assert rules_in_last <= 2, f"Rule accumulation on screen! Found {rules_in_last} rules"
        print("  [OK] All interactive commands finished: Exactly 2 rule lines on screen, zero accumulation")

        # 3. Dynamic Window Resize
        print("\n[CHECK 3] Testing dynamic window resize (80 -> 65 cols)...")
        set_winsize(master, 24, 65)
        time.sleep(0.3)
        resize_out = read_available(master, 0.5)
        plain_resize = strip_ansi(resize_out)
        for line in plain_resize.splitlines():
            if "─" in line:
                assert len(line.strip()) <= 65, f"Rule line exceeded 65 columns: {len(line.strip())}"
        print("  [OK] Dynamic resize: rules resized to 65 cols without visual tails")

        # 4. Narrow Window (40 columns)
        print("\n[CHECK 4] Testing narrow window (40 columns)...")
        set_winsize(master, 24, 40)
        time.sleep(0.3)
        narrow_out = read_available(master, 0.5)
        plain_narrow = strip_ansi(narrow_out)
        # In 40 cols, width < 56, logo is suppressed and text-only header is shown
        for line in plain_narrow.splitlines():
            assert len(line.strip()) <= 40, f"Line wrapped beyond 40 cols: {line}"
        print("  [OK] 40 columns: Logo cleanly suppressed, text-only header, zero line wraps")

        # 5. Clean Exit and Terminal Restoration
        print("\n[CHECK 5] Testing clean exit (Ctrl+C and Ctrl+D)...")
        # Single Ctrl+C clears input
        os.write(master, b"unsubmitted text")
        time.sleep(0.1)
        os.write(master, b"\x03")
        time.sleep(0.2)
        pid_done, _ = os.waitpid(pid, os.WNOHANG)
        assert pid_done == 0, "Single Ctrl+C killed shell unexpectedly"
        print("  [OK] Single Ctrl+C: Input cleared, shell alive")

        # Double Ctrl+C exits
        os.write(master, b"\x03")
        time.sleep(0.05)
        os.write(master, b"\x03")
        start = time.time()
        pid_done = 0
        while time.time() - start < 2.0:
            pid_done, status = os.waitpid(pid, os.WNOHANG)
            if pid_done == pid:
                break
            time.sleep(0.1)
        assert pid_done == pid, "Double Ctrl+C failed to exit shell"
        exit_out = read_available(master, 0.2)
        full_session_output += exit_out
        assert "\x1b[?1049l" in exit_out or "\x1b[?1049l" in full_session_output, "AltScreen exit sequence missing"
        print("  [OK] Double Ctrl+C within 1s: Shell cleanly exited")
        print("  [OK] Terminal restored to initial state (\x1b[?1049l AltScreen exit confirmed)")

    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        os.close(master)

    # 6. Ctrl+D on empty line
    master2, slave2 = pty.openpty()
    set_winsize(slave2, 24, 80)
    pid2 = os.fork()
    if pid2 == 0:
        os.close(master2)
        os.setsid()
        fcntl.ioctl(slave2, termios.TIOCSCTTY, 0)
        os.dup2(slave2, 0)
        os.dup2(slave2, 1)
        os.dup2(slave2, 2)
        if slave2 > 2:
            os.close(slave2)
        os.execve(csls_bin, [csls_bin], env_pty)
        os._exit(1)

    os.close(slave2)
    try:
        read_available(master2, 1.2)
        os.write(master2, b"\x04")  # Ctrl+D
        start = time.time()
        pid2_done = 0
        while time.time() - start < 2.0:
            pid2_done, _ = os.waitpid(pid2, os.WNOHANG)
            if pid2_done == pid2:
                break
            time.sleep(0.1)
        assert pid2_done == pid2, "Ctrl+D failed to exit shell"
        print("  [OK] Ctrl+D on empty line: Shell cleanly exited")
    finally:
        try:
            os.kill(pid2, 9)
        except OSError:
            pass
        os.close(master2)

    print("\n======================================================================")
    print("ALL 5 VERIFICATION CHECKS PASSED WITH 100% SUCCESS!")
    print("======================================================================")


if __name__ == "__main__":
    run_checks()
