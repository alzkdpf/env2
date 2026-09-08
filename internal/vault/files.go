package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// All project IO is constrained by os.Root, in addition to rejecting symlinks.
type Files struct {
	root *os.Root
	Dir  string
}

func OpenFiles(dir string) (*Files, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return &Files{root, abs}, nil
}
func (f *Files) Close() error { return f.root.Close() }
func (f *Files) safe(path string) error {
	if !filepath.IsLocal(path) || path == "." {
		return fmt.Errorf("invalid relative path: %q", path)
	}
	parts := strings.Split(filepath.Clean(path), string(os.PathSeparator))
	for i := range parts {
		info, err := f.root.Lstat(filepath.Join(parts[:i+1]...))
		if errors.Is(err, os.ErrNotExist) && i == len(parts)-1 {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink refused: %q", path)
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular file: %q", path)
		}
	}
	return nil
}
func (f *Files) Read(path string) ([]byte, bool, error) {
	if err := f.safe(path); err != nil {
		return nil, false, err
	}
	r, err := f.root.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, MaxFileSize*2+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > MaxFileSize*2 {
		return nil, false, fmt.Errorf("file too large: %q", path)
	}
	return b, true, nil
}

// Write checks the inspected version again, then replaces through a private temp file.
func (f *Files) Write(path string, data, expected []byte, existed bool, mode os.FileMode) error {
	if err := f.Check(path, expected, existed); err != nil {
		return err
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	temp := filepath.Join(filepath.Dir(path), ".env2-tmp-"+hex.EncodeToString(suffix[:]))
	w, err := f.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.root.Remove(temp)
	if _, err = w.Write(data); err != nil {
		w.Close()
		return err
	}
	if err = w.Sync(); err != nil {
		w.Close()
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	if err = f.Check(path, expected, existed); err != nil {
		return err
	}
	if !existed {
		return f.root.Link(temp, path)
	}
	return f.root.Rename(temp, path)
}
func (f *Files) Check(path string, expected []byte, existed bool) error {
	actual, exists, err := f.Read(path)
	if err != nil {
		return err
	}
	if exists != existed || !bytes.Equal(actual, expected) {
		return fmt.Errorf("file changed since scan; refresh first: %q", path)
	}
	return nil
}
