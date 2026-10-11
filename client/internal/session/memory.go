// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ChatMessage represents a single message turn in the conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// MemoryManager manages persistent project conversation context.
// Strictly banned from using SQLite: uses atomic JSON file replacement.
type MemoryManager struct {
	mu         sync.Mutex
	cwd        string
	memoryFile string
	messages   []ChatMessage
}

// NewMemoryManager initializes memory manager for the given workspace cwd.
func NewMemoryManager(cwd string) *MemoryManager {
	h := sha256.Sum256([]byte(cwd))
	slug := hex.EncodeToString(h[:])[:12]
	projDir := filepath.Join(ConfigDir(), "projects", slug)
	_ = os.MkdirAll(projDir, 0700)
	memFile := filepath.Join(projDir, "chat_memory.json")

	mm := &MemoryManager{
		cwd:        cwd,
		memoryFile: memFile,
		messages:   make([]ChatMessage, 0),
	}
	mm.Load()
	return mm
}

// MemoryFile returns the path to the chat_memory.json file.
func (m *MemoryManager) MemoryFile() string {
	return m.memoryFile
}

// Load loads conversation memory from disk.
func (m *MemoryManager) Load() {
	m.mu.Lock()
	defer m.mu.Unlock()

	raw, err := os.ReadFile(m.memoryFile)
	if err != nil {
		return
	}
	var msgs []ChatMessage
	if err := json.Unmarshal(raw, &msgs); err == nil {
		if len(msgs) > 50 {
			msgs = msgs[len(msgs)-50:]
		}
		m.messages = msgs
	}
}

// Save atomically writes conversation memory to chat_memory.json via .tmp file replacement.
func (m *MemoryManager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	raw, err := json.MarshalIndent(m.messages, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := m.memoryFile + ".tmp"
	if err := os.WriteFile(tmpFile, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, m.memoryFile)
}

// AddTurn records a user query and assistant reply in memory and persists to disk.
func (m *MemoryManager) AddTurn(userMsg, assistantMsg string) error {
	m.mu.Lock()
	m.messages = append(m.messages,
		ChatMessage{Role: "user", Content: userMsg},
		ChatMessage{Role: "assistant", Content: assistantMsg},
	)
	if len(m.messages) > 50 {
		m.messages = m.messages[len(m.messages)-50:]
	}
	m.mu.Unlock()
	return m.Save()
}

// Clear removes all remembered messages and deletes chat_memory.json.
func (m *MemoryManager) Clear() int {
	m.mu.Lock()
	count := len(m.messages)
	m.messages = make([]ChatMessage, 0)
	_ = os.Remove(m.memoryFile)
	m.mu.Unlock()
	return count
}

// Messages returns a copy of current messages.
func (m *MemoryManager) Messages() []ChatMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ChatMessage, len(m.messages))
	copy(out, m.messages)
	return out
}

// EstimateTokens calculates approximate token count (~4 chars per token).
func (m *MemoryManager) EstimateTokens() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	chars := 0
	for _, msg := range m.messages {
		chars += len(msg.Content)
	}
	if chars == 0 {
		return 0
	}
	tokens := chars / 4
	if tokens < 1 {
		tokens = 1
	}
	return tokens
}

// CompactMemory condenses older dialog turns into a structured summary recap.
func (m *MemoryManager) CompactMemory(keepTurns int) (int, error) {
	m.mu.Lock()
	keepCount := keepTurns * 2
	if len(m.messages) <= keepCount {
		m.mu.Unlock()
		return 0, nil
	}

	older := m.messages[:len(m.messages)-keepCount]
	recent := m.messages[len(m.messages)-keepCount:]

	var snippets []string
	for _, msg := range older {
		txt := strings.ReplaceAll(strings.TrimSpace(msg.Content), "\n", " ")
		if len(txt) > 160 {
			txt = txt[:157] + "..."
		}
		snippets = append(snippets, fmt.Sprintf("%s: %s", strings.ToUpper(msg.Role), txt))
	}

	recapContent := "[CONVERSATION SUMMARY - COMPACTED CONTEXT]\n" + strings.Join(snippets, "\n")
	compacted := append([]ChatMessage{{Role: "system", Content: recapContent}}, recent...)
	purged := len(m.messages) - len(compacted)
	m.messages = compacted
	m.mu.Unlock()

	if err := m.Save(); err != nil {
		return purged, err
	}
	return purged, nil
}
