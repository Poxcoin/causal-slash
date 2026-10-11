// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/atotto/clipboard"
)

// CopyToClipboard writes text to all clipboard targets:
// 1. System clipboard via atotto/clipboard (xclip/xsel/wl-copy/Windows/macOS)
// 2. Primary X11 selection (for terminal paste / middle-click on Linux)
// 3. OSC-52 escape sequence (for terminal emulators over SSH, tmux, or local GUI)
func CopyToClipboard(text string) error {
	var firstErr error
	if err := clipboard.WriteAll(text); err != nil {
		firstErr = err
	}

	// Also write to primary selection if xclip is available
	go func() {
		cmd := exec.Command("xclip", "-selection", "primary")
		cmd.Stdin = strings.NewReader(text)
		_ = cmd.Run()
	}()

	// Always emit OSC-52 escape sequence to stdout/tty
	b64 := base64.StdEncoding.EncodeToString([]byte(text))
	osc52 := fmt.Sprintf("\x1b]52;c;%s\x07", b64)

	if tty, openErr := os.OpenFile("/dev/tty", os.O_WRONLY, 0); openErr == nil {
		_, _ = tty.WriteString(osc52)
		_ = tty.Close()
	} else {
		_, _ = os.Stdout.WriteString(osc52)
	}

	return firstErr
}
