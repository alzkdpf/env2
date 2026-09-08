package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/alzkdpf/env2/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

func TestTUIExplicitConflictAndConfirmation(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	e, err := vault.New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	os.WriteFile(filepath.Join(e.Files.Dir, ".env"), []byte("A=SECRET"), 0600)
	if err := e.Apply(e.Inspect(".env"), "encrypt", false); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.Files.Dir, ".env"), []byte("A=LOCAL"), 0600)
	m := New(e)
	updated, _ := m.Update(m.Init()())
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if len(m.pending) != 0 || !strings.Contains(m.message, "differ") {
		t.Fatal("automatic conflict overwrite")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m = updated.(Model)
	if len(m.pending) != 1 {
		t.Fatal("missing confirmation")
	}
	if strings.Contains(m.View(), "SECRET") || strings.Contains(m.View(), "LOCAL") {
		t.Fatal("secret in view")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = updated.(Model)
	if len(m.pending) != 0 {
		t.Fatal("cancel failed")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m = updated.(Model)
	if cmd == nil || !m.busy {
		t.Fatal("confirmation did not apply")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	b, _ := os.ReadFile(filepath.Join(e.Files.Dir, ".env"))
	if string(b) != "A=SECRET" {
		t.Fatal("wrong direction")
	}
	if m.busy || m.entries[0].State != vault.Same {
		t.Fatal("not refreshed")
	}
}
