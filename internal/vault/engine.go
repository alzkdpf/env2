package vault

import (
	"bytes"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
)

type State string

const (
	Plain    State = "plaintext only"
	Sealed   State = "encrypted only"
	Same     State = "in sync"
	Conflict State = "different"
	Broken   State = "error"
)

type Entry struct {
	Path                string
	State               State
	Err                 error
	plain, cipher       []byte
	hasPlain, hasCipher bool
}
type Engine struct {
	Files *Files
	Key   *age.X25519Identity
}

func New(dir string, key *age.X25519Identity) (*Engine, error) {
	f, err := OpenFiles(dir)
	if err != nil {
		return nil, err
	}
	return &Engine{f, key}, nil
}
func (e *Engine) Close() error { return e.Files.Close() }
func IsEnv(name string) bool {
	if strings.HasSuffix(name, ".enc") || strings.HasPrefix(name, ".env2-") {
		return false
	}
	at := strings.Index(name, ".env")
	if at < 0 {
		return false
	}
	rest := name[at+4:]
	if rest != "" && !strings.HasPrefix(rest, ".") {
		return false
	}
	for _, part := range strings.Split(rest, ".") {
		switch part {
		case "example", "sample", "template":
			return false
		}
	}
	return true
}
func (e *Engine) Scan() ([]Entry, error) {
	paths := map[string]bool{}
	err := fs.WalkDir(e.Files.root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".env2", "node_modules", "vendor", ".venv", "dist", "build":
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		base := strings.TrimSuffix(d.Name(), ".enc")
		if IsEnv(base) {
			paths[strings.TrimSuffix(filepath.FromSlash(path), ".enc")] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sorted := make([]string, 0, len(paths))
	for path := range paths {
		sorted = append(sorted, path)
	}
	sort.Strings(sorted)
	entries := make([]Entry, 0, len(sorted))
	for _, path := range sorted {
		entries = append(entries, e.Inspect(path))
	}
	return entries, nil
}
func (e *Engine) Inspect(path string) Entry {
	item := Entry{Path: path}
	if !IsEnv(filepath.Base(path)) {
		item.State = Broken
		item.Err = fmt.Errorf("not an environment filename")
		return item
	}
	item.plain, item.hasPlain, item.Err = e.Files.Read(path)
	if item.Err == nil {
		item.cipher, item.hasCipher, item.Err = e.Files.Read(path + ".enc")
	}
	if item.Err != nil {
		item.State = Broken
		return item
	}
	if len(item.plain) > MaxFileSize {
		item.State = Broken
		item.Err = fmt.Errorf("plaintext exceeds 16 MiB")
		return item
	}
	if !item.hasPlain && !item.hasCipher {
		item.State = Broken
		item.Err = fmt.Errorf("file not found")
		return item
	}
	if !item.hasCipher {
		item.State = Plain
		return item
	}
	decoded, err := Decrypt(item.cipher, e.Key)
	if err != nil {
		item.State = Broken
		item.Err = err
		return item
	}
	defer clear(decoded)
	if !item.hasPlain {
		item.State = Sealed
	} else if bytes.Equal(item.plain, decoded) {
		item.State = Same
	} else {
		item.State = Conflict
	}
	return item
}
func (e *Engine) Apply(item Entry, action string, overwrite bool) error {
	if item.Err != nil {
		return item.Err
	}
	if item.State == Conflict && !overwrite {
		return fmt.Errorf("contents differ: explicitly choose encrypt/decrypt with --force")
	}
	if err := e.Files.Check(item.Path, item.plain, item.hasPlain); err != nil {
		return err
	}
	if err := e.Files.Check(item.Path+".enc", item.cipher, item.hasCipher); err != nil {
		return err
	}
	if action != "encrypt" && action != "decrypt" {
		return fmt.Errorf("unknown action")
	}
	if action == "encrypt" && !item.hasPlain {
		return fmt.Errorf("no plaintext")
	}
	if action == "decrypt" && !item.hasCipher {
		return fmt.Errorf("no ciphertext")
	}
	if err := e.Protect(item.Path); err != nil {
		return err
	}
	if item.State == Same {
		return nil
	}
	if action == "encrypt" {
		data, err := Encrypt(item.plain, e.Key.Recipient())
		if err != nil {
			return err
		}
		return e.Files.Write(item.Path+".enc", data, item.cipher, item.hasCipher, 0600)
	}
	data, err := Decrypt(item.cipher, e.Key)
	if err != nil {
		return err
	}
	defer clear(data)
	return e.Files.Write(item.Path, data, item.plain, item.hasPlain, 0600)
}
