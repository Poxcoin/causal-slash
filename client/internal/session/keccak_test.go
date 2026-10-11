// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session_test

import (
	"encoding/hex"
	"testing"

	"csls/internal/session"
)

func TestKeccak256(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{
			"",
			"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"hello",
			"1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
		},
	}

	for _, tc := range cases {
		out := session.Keccak256([]byte(tc.input))
		outHex := hex.EncodeToString(out[:])
		if outHex != tc.expected {
			t.Fatalf("for %q expected %s, got %s", tc.input, tc.expected, outHex)
		}
	}
}
