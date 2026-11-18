// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	loadErr    error
}

// NewMemoryManager initializes memory manager for the given workspace cwd.
func NewMemoryManager(cwd string) *MemoryManager {
	h := sha256.Sum256([]byte(cwd))
	slug := hex.EncodeToString(h[:])[:12]
	projDir := filepath.Join(ConfigDir(), "projects", slug)
	memFile := filepath.Join(projDir, "chat_memory.json")

	mm := &MemoryManager{
		cwd:        cwd,
		memoryFile: memFile,
		messages:   make([]ChatMessage, 0),
	}
	if err := mm.Load(); err != nil {
		mm.loadErr = err
	}
	return mm
}

// MemoryFile returns the path to the chat_memory.json file.
func (m *MemoryManager) MemoryFile() string {
	return m.memoryFile
}

// LoadError reports a failed load. Saves remain blocked until Load succeeds or
// the user explicitly clears the history, so corrupt files are never replaced.
func (m *MemoryManager) LoadError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadErr
}

// Load loads conversation memory from disk, retaining existing messages on error.
func (m *MemoryManager) Load() (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() { m.loadErr = err }()

	raw, err := os.ReadFile(m.memoryFile)
	if os.IsNotExist(err) {
		m.messages = make([]ChatMessage, 0)
		return nil
	}
	if err != nil {
		return fmt.Errorf("load conversation memory: %w", err)
	}
	var msgs []ChatMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return fmt.Errorf("decode conversation memory %s: %w", m.memoryFile, err)
	}
	if msgs == nil {
		return fmt.Errorf("decode conversation memory %s: expected a JSON message array", m.memoryFile)
	}
	for i, msg := range msgs {
		switch msg.Role {
		case "user", "assistant", "system":
		default:
			return fmt.Errorf("decode conversation memory %s: invalid role %q at message %d", m.memoryFile, msg.Role, i)
		}
	}
	if len(msgs) > 50 {
		msgs = msgs[len(msgs)-50:]
	}
	m.messages = msgs
	return nil
}

// Save atomically writes conversation memory using a private temporary file.
func (m *MemoryManager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

func (m *MemoryManager) saveLocked() error {
	if m.loadErr != nil {
		return fmt.Errorf("refusing to overwrite unreadable conversation history: %w", m.loadErr)
	}
	raw, err := json.MarshalIndent(m.messages, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(m.memoryFile, raw)
}

// writeAtomicFile preserves the previous file if writing the replacement fails.
func writeAtomicFile(path string, data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create persistence directory: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create persistence file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if removeErr := os.Remove(tmp); removeErr != nil && !os.IsNotExist(removeErr) {
			err = errors.Join(err, fmt.Errorf("remove temporary persistence file: %w", removeErr))
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return fmt.Errorf("write persistence file %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace persistence file %s: %w", path, err)
	}
	return nil
}

// AddTurn records a user query and assistant reply in memory and persists to disk.
func (m *MemoryManager) AddTurn(userMsg, assistantMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.messages
	m.messages = append(append([]ChatMessage(nil), previous...),
		ChatMessage{Role: "user", Content: userMsg},
		ChatMessage{Role: "assistant", Content: assistantMsg},
	)
	if len(m.messages) > 50 {
		m.messages = m.messages[len(m.messages)-50:]
	}
	if err := m.saveLocked(); err != nil {
		m.messages = previous
		return err
	}
	return nil
}

// Clear removes all remembered messages and deletes chat_memory.json.
func (m *MemoryManager) Clear() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := len(m.messages)
	if err := os.Remove(m.memoryFile); err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("clear conversation memory: %w", err)
	}
	m.messages = make([]ChatMessage, 0)
	m.loadErr = nil
	return count, nil
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
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return 0, fmt.Errorf("cannot compact unreadable conversation history: %w", m.loadErr)
	}
	if keepTurns < 0 {
		return 0, fmt.Errorf("keepTurns must not be negative")
	}
	if keepTurns > len(m.messages)/2 {
		return 0, nil
	}
	keepCount := keepTurns * 2
	if len(m.messages) <= keepCount {
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
	previous := m.messages
	m.messages = compacted

	if err := m.saveLocked(); err != nil {
		m.messages = previous
		return 0, err
	}
	return purged, nil
}

// InputHistoryFile returns ~/.csls/input_history
func InputHistoryFile() string {
	return filepath.Join(ConfigDir(), "input_history")
}

// LoadInputHistory loads past shell inputs from disk.
func LoadInputHistory() []string {
	raw, err := os.ReadFile(InputHistoryFile())
	if err != nil {
		return nil
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	if len(out) > 500 {
		out = out[len(out)-500:]
	}
	return out
}

// AppendInputHistory appends a single command/prompt to ~/.csls/input_history.
// Consecutive duplicate commands are suppressed.
func AppendInputHistory(input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	if raw, err := os.ReadFile(InputHistoryFile()); err == nil {
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == input {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read input history before append: %w", err)
	}
	if err := os.MkdirAll(ConfigDir(), 0700); err != nil {
		return fmt.Errorf("create input history directory: %w", err)
	}
	f, err := os.OpenFile(InputHistoryFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open input history: %w", err)
	}
	_, writeErr := f.WriteString(input + "\n")
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return fmt.Errorf("append input history: %w", err)
	}
	return nil
}
