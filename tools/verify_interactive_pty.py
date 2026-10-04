# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Full end-to-end interactive PTY verification of csls terminal shell.
Simulates a real interactive user typing commands, checking visual rendering,
and verifying clean exit without any tracebacks.
"""

import os
import pty
import select
import sys
import time
import fcntl
import termios
import struct


def main():
    print("Starting interactive PTY verification of `csls`...")
    # Ensure wallet is initialized with testnet bond for shell test
    w_path = os.path.expanduser("~/.csls/wallet.json")
    if os.path.exists(w_path):
        import json
        with open(w_path, "r") as f:
            d = json.load(f)
        d["collateral_bond"] = 10.0
        d["status"] = "ready"
        with open(w_path, "w") as f:
            json.dump(d, f, indent=2)

    master, slave = pty.openpty()

    # Set terminal window size to 80x24
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

    pid = os.fork()
    if pid == 0:
        # Child process: run csls interactively
        os.close(master)
        os.setsid()
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.close(slave)
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLORTERM"] = "truecolor"
        os.execvp("csls", ["csls"])
        sys.exit(1)

    os.close(slave)

    output = bytearray()

    def pump(timeout=1.0):
        start = time.time()
        while time.time() - start < timeout:
            r, _, _ = select.select([master], [], [], 0.05)
            if r:
                try:
                    data = os.read(master, 4096)
                    if not data:
                        break
                    output.extend(data)
                    # If prompt_toolkit queries cursor position report \x1b[6n, respond
                    if b"\x1b[6n" in data:
                        os.write(master, b"\x1b[10;1R")
                except OSError:
                    break

    def send_cmd(cmd_text, delay_after=0.4):
        os.write(master, cmd_text.encode("utf-8"))
        pump(delay_after)

    # 1. Wait for initial header and prompt
    pump(0.8)
    initial_text = output.decode("utf-8", errors="replace")
    assert "Causal-Slash CLI 0.3.0" in initial_text, "Header title missing!"
    assert "Sovereign M2M clearing" in initial_text, "Tagline missing!"
    print("✓ Launch header verified")

    # 2. Check toolbar and shortcuts
    assert "for shortcuts" in initial_text, "Toolbar 'for shortcuts' missing!"
    assert "bond:" in initial_text, "Toolbar 'bond:' missing!"
    print("✓ Bottom toolbar verified")

    # 3. Test '?' shortcut panel
    send_cmd("?\n", delay_after=0.5)
    out_shortcuts = output.decode("utf-8", errors="replace")
    assert "Keyboard Shortcuts" in out_shortcuts, "Shortcuts panel missing!"
    print("✓ Shortcuts panel verified")

    # 4. Test /help
    send_cmd("/help\n", delay_after=0.5)
    out_help = output.decode("utf-8", errors="replace")
    assert "Commands" in out_help, "Commands header missing!"
    assert "/wallet" in out_help, "/wallet in help table missing!"
    assert "/daemon" in out_help, "/daemon in help table missing!"
    assert "/bond" in out_help, "/bond in help table missing!"
    assert "/verify" in out_help, "/verify in help table missing!"
    print("✓ /help table verified")

    # 5. Test unknown command with suggestion
    send_cmd("/daemn\n", delay_after=0.5)
    out_typo = output.decode("utf-8", errors="replace")
    assert "Unknown command: /daemn" in out_typo, "Unknown command error missing!"
    assert "Did you mean" in out_typo and "/daemon" in out_typo, "Suggestion missing!"
    print("✓ Unknown command & suggestion verified")

    # 6. Test free text to agent
    send_cmd("who are you\n", delay_after=0.5)
    out_agent = output.decode("utf-8", errors="replace")
    assert "agent backend not configured" in out_agent, "Agent backend response missing!"
    print("✓ Free-text routing to agent verified")

    # 7. Test /bond command
    send_cmd("/bond\n", delay_after=0.5)
    out_bond = output.decode("utf-8", errors="replace")
    assert "Base L2 Collateral Bond Status:" in out_bond, "Bond status missing!"
    print("✓ /bond execution verified")

    # 8. Test /verify command
    send_cmd("/verify\n", delay_after=0.5)
    out_verify = output.decode("utf-8", errors="replace")
    assert "PerformanceCollateralVault" in out_verify, "Verify output missing contract!"
    print("✓ /verify execution verified")

    # 9. Test /exit
    send_cmd("/exit\n", delay_after=0.5)
    _, status = os.waitpid(pid, 0)
    exit_code = os.waitstatus_to_exitcode(status)
    assert exit_code == 0, f"Expected exit code 0, got {exit_code}"
    print(f"✓ /exit cleanly terminated shell with exit code {exit_code}")

    # Check for any tracebacks across the whole session
    full_output = output.decode("utf-8", errors="replace")
    assert "Traceback" not in full_output, f"Traceback detected in output:\n{full_output}"
    print("✓ Zero tracebacks confirmed across full interactive session!")
    print("\nALL INTERACTIVE VERIFICATIONS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    main()
