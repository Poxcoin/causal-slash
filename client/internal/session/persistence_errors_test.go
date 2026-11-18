// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMemoryCreatesDirectoryOnlyOnSave(t *testing.T) {
	home := filepath.Join(t.TempDir(), "new-home")
	t.Setenv("CSLS_HOME", home)
	m := NewMemoryManager("workspace")
	if m.LoadError() != nil {
		t.Fatal(m.LoadError())
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("constructor created directory or unexpected stat error: %v", err)
	}
	if err := m.AddTurn("question", "answer"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(m.MemoryFile())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("memory permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestCorruptMemoryCannotBeOverwritten(t *testing.T) {
	for _, corrupt := range []string{"{broken", "null", "[null]", "[{}]", `[{"role":"invalid","content":"keep me"}]`} {
		t.Run(corrupt, func(t *testing.T) {
			t.Setenv("CSLS_HOME", t.TempDir())
			m := NewMemoryManager("workspace")
			if err := m.Save(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(m.MemoryFile(), []byte(corrupt), 0600); err != nil {
				t.Fatal(err)
			}
			m = NewMemoryManager("workspace")
			if m.LoadError() == nil {
				t.Fatal("corrupt load must be observable")
			}
			if err := m.Save(); err == nil {
				t.Fatal("Save overwrote corrupt history")
			}
			if err := m.AddTurn("new question", "new answer"); err == nil {
				t.Fatal("AddTurn accepted corrupt history")
			}
			if n, err := m.CompactMemory(0); err == nil || n != 0 {
				t.Fatalf("CompactMemory = %d, %v; want 0, error", n, err)
			}
			raw, err := os.ReadFile(m.MemoryFile())
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != corrupt || len(m.Messages()) != 0 {
				t.Fatalf("failed writes changed history: disk=%q messages=%v", raw, m.Messages())
			}
			if _, err := m.Clear(); err != nil {
				t.Fatal(err)
			}
			if m.LoadError() != nil {
				t.Fatal("explicit successful Clear must release load error")
			}
			if err := m.AddTurn("after clear", "answer"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemoryReloadRecovery(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	m := NewMemoryManager("workspace")
	if err := m.AddTurn("old", "answer"); err != nil {
		t.Fatal(err)
	}
	before := m.Messages()
	if err := os.WriteFile(m.MemoryFile(), []byte("bad json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err == nil {
		t.Fatal("Load must report corruption")
	}
	if !reflect.DeepEqual(m.Messages(), before) {
		t.Fatal("failed Load replaced existing messages")
	}
	if err := os.WriteFile(m.MemoryFile(), []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.LoadError() != nil || len(m.Messages()) != 0 {
		t.Fatal("successful Load did not recover")
	}
	if err := m.AddTurn("recovered", "answer"); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryFailedWritesAndClearRetainMessages(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	m := NewMemoryManager("workspace")
	for i := 0; i < 3; i++ {
		if err := m.AddTurn("question", "answer"); err != nil {
			t.Fatal(err)
		}
	}
	before := m.Messages()
	if err := os.Remove(m.MemoryFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(m.MemoryFile(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.MemoryFile(), "blocker"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.AddTurn("must not remain", "answer"); err == nil {
		t.Fatal("AddTurn must report rename failure")
	}
	if n, err := m.CompactMemory(1); err == nil || n != 0 {
		t.Fatalf("CompactMemory = %d, %v; want 0, error", n, err)
	}
	if n, err := m.Clear(); err == nil || n != 0 {
		t.Fatalf("Clear = %d, %v; want 0, error", n, err)
	}
	if !reflect.DeepEqual(m.Messages(), before) {
		t.Fatalf("failed persistence changed memory: %v", m.Messages())
	}
	entries, err := os.ReadDir(filepath.Dir(m.MemoryFile()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(m.MemoryFile()) {
		t.Fatalf("failed atomic replacement left temporary files: %v", entries)
	}
}

func TestPersistenceReportsBlockedDirectory(t *testing.T) {
	home := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(home, []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSLS_HOME", home)
	m := NewMemoryManager("workspace")
	if m.LoadError() == nil {
		t.Fatal("constructor must retain read failure")
	}
	checks := map[string]func() error{
		"memory":  m.Save,
		"model":   func() error { return SaveActiveModel("provider:model") },
		"theme":   func() error { return SaveTheme("neon-amber") },
		"history": func() error { return AppendInputHistory("question") },
	}
	for name, save := range checks {
		if err := save(); err == nil {
			t.Errorf("%s persistence must report blocked directory", name)
		}
	}
}

func TestMemorySaveReportsDirectoryCreationFailure(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("CSLS_HOME", home)
	m := NewMemoryManager("workspace")
	if m.LoadError() != nil {
		t.Fatal(m.LoadError())
	}
	if err := os.WriteFile(home, []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(); err == nil {
		t.Fatal("Save must report failed directory creation")
	}
}

func TestModelPersistenceAndRemovalErrors(t *testing.T) {
	t.Setenv("CSLS_HOME", filepath.Join(t.TempDir(), "new-home"))
	if err := SaveActiveModel(" provider:model "); err != nil {
		t.Fatal(err)
	}
	if got := LoadActiveModel(); got != "provider:model" {
		t.Fatalf("loaded model = %q", got)
	}
	for i := 0; i < 2; i++ {
		if err := SaveActiveModel(""); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(ActiveModelFile(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ActiveModelFile(), "blocker"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveActiveModel(""); err == nil {
		t.Fatal("model removal failure must be returned")
	}
}

func TestFailedThemeSaveKeepsCachedTheme(t *testing.T) {
	t.Setenv("CSLS_HOME", t.TempDir())
	themeMu.Lock()
	previous := cachedTheme
	themeMu.Unlock()
	t.Cleanup(func() {
		themeMu.Lock()
		cachedTheme = previous
		themeMu.Unlock()
	})
	if err := SaveTheme("neon-amber"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ThemeFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ThemeFile(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveTheme("cyberpunk-cyan"); err == nil {
		t.Fatal("theme save must report failed replacement")
	}
	if got := LoadTheme(); got != "neon-amber" {
		t.Fatalf("failed save changed theme cache to %q", got)
	}
}

func TestInputHistoryCreatesDirectoryAndReportsReadFailure(t *testing.T) {
	t.Setenv("CSLS_HOME", filepath.Join(t.TempDir(), "new-home"))
	if err := AppendInputHistory("first"); err != nil {
		t.Fatal(err)
	}
	if got := LoadInputHistory(); !reflect.DeepEqual(got, []string{"first"}) {
		t.Fatalf("unexpected history: %v", got)
	}
	if err := os.Remove(InputHistoryFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(InputHistoryFile(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := AppendInputHistory("must fail"); err == nil {
		t.Fatal("input history read failure must not be ignored")
	}
}
