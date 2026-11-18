// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/atotto/clipboard"
)

// CopyToClipboard writes text to all clipboard targets:
// 1. System clipboard via atotto/clipboard
// 2. Direct xclip / xsel calls to both 'clipboard' and 'primary' selections (Linux desktop)
// 3. OSC-52 escape sequence (for terminal emulators over SSH, tmux, or local GUI)
func CopyToClipboard(text string) error {
	var firstErr error

	// 1. atotto/clipboard
	if err := clipboard.WriteAll(text); err != nil {
		firstErr = err
	}

	// 2. Direct xclip to clipboard and primary
	if _, err := exec.LookPath("xclip"); err == nil {
		// Write to clipboard selection
		cmdClip := exec.Command("xclip", "-selection", "clipboard")
		cmdClip.Stdin = strings.NewReader(text)

		// Write to primary selection (for middle-click / terminal selection)
		cmdPrim := exec.Command("xclip", "-selection", "primary")
		cmdPrim.Stdin = strings.NewReader(text)
		firstErr = clipboardCommandErrors(firstErr, text, cmdClip, cmdPrim)
	} else if _, err := exec.LookPath("xsel"); err == nil {
		cmdClip := exec.Command("xsel", "--clipboard", "--input")
		cmdClip.Stdin = strings.NewReader(text)

		cmdPrim := exec.Command("xsel", "--primary", "--input")
		cmdPrim.Stdin = strings.NewReader(text)
		firstErr = clipboardCommandErrors(firstErr, text, cmdClip, cmdPrim)
	} else if _, err := exec.LookPath("wl-copy"); err == nil {
		cmdWl := exec.Command("wl-copy")
		cmdWl.Stdin = strings.NewReader(text)

		cmdWlPrim := exec.Command("wl-copy", "--primary")
		cmdWlPrim.Stdin = strings.NewReader(text)
		firstErr = clipboardCommandErrors(firstErr, text, cmdWl, cmdWlPrim)
	}

	// 3. Always emit OSC-52 escape sequence to stdout/tty
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

// A direct backend replaces the fallback error only if every selection succeeds.
func clipboardCommandErrors(fallbackErr error, text string, commands ...*exec.Cmd) error {
	var runErrors []error
	for _, cmd := range commands {
		cmd.Stdin = strings.NewReader(text)
		if runErr := cmd.Run(); runErr != nil {
			runErrors = append(runErrors, fmt.Errorf("%s: %w", cmd.Path, runErr))
		}
	}
	if len(runErrors) == 0 {
		return nil
	}
	return errors.Join(append(runErrors, fallbackErr)...)
}
