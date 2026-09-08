package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/alzkdpf/env2/internal/tui"
	"github.com/alzkdpf/env2/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "env2:", err)
		os.Exit(1)
	}
}
func run() error {
	defaultDir, err := vault.DefaultKeyDir()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("env2", flag.ContinueOnError)
	dir := flags.String("dir", ".", "project directory")
	keyDir := flags.String("key-dir", defaultDir, "encrypted key directory")
	stdin := flags.Bool("password-stdin", false, "read one passphrase line from stdin (automation)")
	force := flags.Bool("force", false, "explicitly replace a different destination (CLI only)")
	showVersion := flags.Bool("version", false, "print version")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `env2 — encrypted environment files, ready for Git

Usage: env2 [flags] [command]

No command opens the TUI. Flags precede commands.
  init                  create a passphrase-protected key
  status                inspect environment file pairs
  sync                  encrypt/decrypt unambiguous pairs
  encrypt FILE...       encrypt selected environment files
  decrypt FILE...       decrypt selected files (.enc suffix optional)
  key export FILE       export encrypted key backup (never overwrite)
  key import FILE       restore encrypted key into an empty key directory

`)
		flags.PrintDefaults()
	}
	if err = flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println("env2", version)
		return nil
	}
	args := flags.Args()
	command := "tui"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "tui", "init", "status", "sync":
		if len(args) > 1 {
			return fmt.Errorf("%s takes no arguments", command)
		}
	case "encrypt", "decrypt":
		if len(args) < 2 {
			return fmt.Errorf("provide at least one file")
		}
	case "key":
		if len(args) != 3 || (args[1] != "export" && args[1] != "import") {
			return fmt.Errorf("use key export FILE or key import FILE")
		}
	default:
		return fmt.Errorf("unknown command %q; use --help", command)
	}
	if command == "tui" && (*stdin || !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd()))) {
		return fmt.Errorf("TUI needs an interactive terminal; use status, sync, encrypt or decrypt")
	}
	exists, err := vault.KeyExists(*keyDir)
	if err != nil {
		return err
	}
	importing := command == "key" && args[1] == "import"
	creating := !exists && !importing && (command == "tui" || command == "init")
	if command == "init" && exists {
		return fmt.Errorf("key already exists; use env2 to unlock it")
	}
	if importing && exists {
		return fmt.Errorf("key already exists; import into an empty --key-dir")
	}
	if !exists && !creating && !importing {
		return fmt.Errorf("no local key; run env2 init or env2 key import BACKUP")
	}
	if creating {
		fmt.Fprintln(os.Stderr, "Create your env2 key. Use a strong passphrase (at least 12 bytes).")
	}
	password, err := readPassword(*stdin, creating)
	if err != nil {
		return err
	}
	defer clear(password)
	if command == "key" {
		if importing {
			err = vault.ImportKey(*keyDir, args[2], string(password))
		} else {
			err = vault.ExportKey(*keyDir, args[2], string(password))
		}
		if err == nil {
			fmt.Println("Encrypted key", args[1]+"ed.")
		}
		return err
	}
	var key *age.X25519Identity
	if creating {
		key, err = vault.CreateKey(*keyDir, string(password))
	} else {
		key, err = vault.LoadKey(*keyDir, string(password))
	}
	clear(password)
	if err != nil {
		return err
	}
	if creating {
		fmt.Fprintln(os.Stderr, "Key created. Back it up with: env2 key export /safe/location/env2-key.age\nA passphrase alone cannot recover files if this key is lost.")
	}
	if command == "init" {
		return nil
	}
	engine, err := vault.New(*dir, key)
	if err != nil {
		return err
	}
	defer engine.Close()
	if command == "tui" {
		_, err = tea.NewProgram(tui.New(engine), tea.WithAltScreen()).Run()
		return err
	}
	if command == "encrypt" || command == "decrypt" {
		for _, path := range args[1:] {
			if command == "decrypt" {
				path = strings.TrimSuffix(path, ".enc")
			}
			if filepath.IsAbs(path) {
				path, err = filepath.Rel(engine.Files.Dir, path)
				if err != nil {
					return err
				}
			}
			item := engine.Inspect(filepath.Clean(path))
			if err = engine.Apply(item, command, *force); err != nil {
				return fmt.Errorf("%q: %w", path, err)
			}
			fmt.Printf("%s %q\n", command, path)
		}
		return nil
	}
	entries, err := engine.Scan()
	if err != nil {
		return err
	}
	if command == "status" {
		failed := false
		for _, e := range entries {
			fmt.Printf("%-19s %q\n", e.State, e.Path)
			if e.Err != nil {
				fmt.Fprintf(os.Stderr, "%q: %v\n", e.Path, e.Err)
				failed = true
			}
		}
		if failed {
			return fmt.Errorf("some files could not be inspected")
		}
		return nil
	}
	// Preflight every pair before applying any automatic operation.
	for _, e := range entries {
		if e.Err != nil {
			return fmt.Errorf("%q: %w", e.Path, e.Err)
		}
		if e.State == vault.Conflict {
			return fmt.Errorf("%q differs; explicitly encrypt/decrypt with --force", e.Path)
		}
	}
	for _, e := range entries {
		action := "encrypt"
		if e.State == vault.Sealed {
			action = "decrypt"
		}
		if err = engine.Apply(e, action, false); err != nil {
			return fmt.Errorf("%q: %w", e.Path, err)
		}
		fmt.Printf("%-19s %q\n", e.State, e.Path)
	}
	return nil
}
func readPassword(stdin, confirm bool) ([]byte, error) {
	if stdin {
		line, err := bufio.NewReader(io.LimitReader(os.Stdin, 4098)).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if len(line) == 0 || len(line) > 4096 {
			return nil, fmt.Errorf("passphrase must contain 1–4096 bytes")
		}
		return []byte(line), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("use a terminal or explicitly pass --password-stdin")
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		clear(pass)
		return nil, fmt.Errorf("empty passphrase")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			clear(pass)
			return nil, err
		}
		same := string(pass) == string(second)
		clear(second)
		if !same {
			clear(pass)
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return pass, nil
}
