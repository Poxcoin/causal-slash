// SPDX-License-Identifier: Apache-2.0
package session

import (
	"errors"
	"os/exec"
	"testing"
)

func TestClipboardCommandErrors(t *testing.T) {
	fallback := errors.New("system clipboard unavailable")
	for _, tc := range []struct {
		name          string
		first, second string
		wantErr       bool
	}{
		{"both succeed", "exit 0", "exit 0", false},
		{"clipboard fails", "exit 7", "exit 0", true},
		{"primary fails", "exit 0", "exit 8", true},
		{"both fail", "exit 7", "exit 8", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := clipboardCommandErrors(fallback, "copied text", exec.Command("sh", "-c", tc.first), exec.Command("sh", "-c", tc.second))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr = %t", err, tc.wantErr)
			}
			if tc.wantErr {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || !errors.Is(err, fallback) {
					t.Fatalf("lost command or fallback error: %v", err)
				}
			}
		})
	}
}
