package tui

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/alzkdpf/env2/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type loaded struct {
	entries []vault.Entry
	err     error
	message string
}
type job struct {
	entry  vault.Entry
	action string
}
type Model struct {
	engine                *vault.Engine
	entries               []vault.Entry
	selected              map[string]bool
	cursor, width, height int
	busy                  bool
	pending               []job
	message               string
}

func New(engine *vault.Engine) Model {
	return Model{engine: engine, selected: map[string]bool{}, width: 90, height: 24, busy: true}
}
func (m Model) scan(message string) tea.Cmd {
	return func() tea.Msg { entries, err := m.engine.Scan(); return loaded{entries, err, message} }
}
func (m Model) Init() tea.Cmd { return m.scan("") }
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case loaded:
		m.busy = false
		m.pending = nil
		m.selected = map[string]bool{}
		m.entries = msg.entries
		m.message = msg.message
		if msg.err != nil {
			m.message = "Scan failed: " + msg.err.Error()
		}
		if m.cursor >= len(m.entries) {
			m.cursor = max(0, len(m.entries)-1)
		}
	case tea.KeyMsg:
		key := msg.String()
		if m.busy {
			return m, nil
		}
		if key == "ctrl+c" || key == "q" {
			return m, tea.Quit
		}
		if len(m.pending) > 0 {
			if key == "esc" || key == "n" {
				m.pending = nil
				return m, nil
			}
			if key == "y" {
				jobs := append([]job(nil), m.pending...)
				m.busy = true
				return m, func() tea.Msg {
					done := 0
					var failure string
					for _, j := range jobs {
						if err := m.engine.Apply(j.entry, j.action, true); err != nil {
							failure = fmt.Sprintf("Stopped at %s: %v", j.entry.Path, err)
							break
						}
						done++
					}
					entries, err := m.engine.Scan()
					message := fmt.Sprintf("Applied %d file(s). Commit .enc files and .gitignore changes.", done)
					if failure != "" {
						message = fmt.Sprintf("Applied %d. %s", done, failure)
					}
					return loaded{entries, err, message}
				}
			}
			return m, nil
		}
		switch key {
		case "up", "k":
			m.cursor = max(0, m.cursor-1)
		case "down", "j":
			m.cursor = min(len(m.entries)-1, m.cursor+1)
		case "r":
			m.busy = true
			return m, m.scan("Refreshed.")
		case " ":
			if len(m.entries) > 0 {
				p := m.entries[m.cursor].Path
				m.selected[p] = !m.selected[p]
			}
		case "a":
			for _, e := range m.entries {
				if e.State == vault.Plain || e.State == vault.Sealed {
					m.selected[e.Path] = true
				}
			}
		case "enter", "e", "d":
			chosen := []vault.Entry{}
			for _, e := range m.entries {
				if m.selected[e.Path] {
					chosen = append(chosen, e)
				}
			}
			if len(chosen) == 0 && len(m.entries) > 0 {
				chosen = append(chosen, m.entries[m.cursor])
			}
			for _, e := range chosen {
				if e.Err != nil {
					m.message = e.Err.Error()
					m.pending = nil
					return m, nil
				}
				action := ""
				switch key {
				case "e":
					action = "encrypt"
				case "d":
					action = "decrypt"
				default:
					switch e.State {
					case vault.Plain:
						action = "encrypt"
					case vault.Sealed:
						action = "decrypt"
					case vault.Conflict:
						m.message = "Contents differ. Choose E (plaintext wins) or D (encrypted file wins)."
						m.pending = nil
						return m, nil
					}
				}
				if action != "" {
					m.pending = append(m.pending, job{e, action})
				}
			}
			if len(m.pending) == 0 {
				m.message = "Already in sync."
			}
		}
	}
	return m, nil
}
func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
}
func (m Model) View() string {
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	warning := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	var b strings.Builder
	b.WriteString("\n  " + accent.Render("env2") + "  /  local secrets, ready for Git\n")
	b.WriteString("  " + muted.Render(ansi.Truncate(safe(m.engine.Files.Dir), max(10, m.width-4), "…")) + "\n\n")
	if m.busy {
		b.WriteString("  Working…\n")
		return b.String()
	}
	if len(m.entries) == 0 {
		b.WriteString("  No environment files found. Add .env or .env.local, then press R.\n")
	}
	rows := max(1, m.height-13)
	start := max(0, m.cursor-rows+1)
	for i := start; i < min(len(m.entries), start+rows); i++ {
		e := m.entries[i]
		pointer := " "
		if i == m.cursor {
			pointer = ">"
		}
		mark := "[ ]"
		if m.selected[e.Path] {
			mark = "[x]"
		}
		state := string(e.State)
		if e.Err != nil {
			state = "error"
		}
		line := fmt.Sprintf("%s %s %-19s %s", pointer, mark, state, safe(e.Path))
		line = ansi.Truncate(line, max(10, m.width-4), "…")
		if i == m.cursor {
			line = accent.Render(line)
		} else if e.State == vault.Conflict || e.Err != nil {
			line = warning.Render(line)
		}
		b.WriteString("  " + line + "\n")
	}
	b.WriteString(fmt.Sprintf("\n  %d files · secrets are never displayed\n", len(m.entries)))
	if len(m.pending) > 0 {
		b.WriteString("\n" + warning.Render("  Apply the following actions? Existing destinations will be replaced.") + "\n")
		for i, j := range m.pending {
			if i >= 3 {
				b.WriteString(fmt.Sprintf("  … and %d more\n", len(m.pending)-i))
				break
			}
			b.WriteString("  " + j.action + " " + safe(j.entry.Path) + "\n")
		}
		b.WriteString("  Y apply · N/Esc cancel\n")
	} else {
		if m.message != "" {
			b.WriteString("\n  " + ansi.Truncate(safe(m.message), max(10, m.width-4), "…") + "\n")
		}
		b.WriteString("\n  ↑↓ move · Space select · A select new · Enter auto\n  E encrypt · D decrypt · R refresh · Q quit\n")
	}
	return b.String()
}
