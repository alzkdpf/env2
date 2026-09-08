package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const KeyName = "env2.age"

func DefaultKeyDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".env2"), nil
}
func KeyExists(dir string) (bool, error) {
	info, err := os.Lstat(filepath.Join(dir, KeyName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("key must be a regular file")
	}
	return true, nil
}
func keyFiles(dir string) (*Files, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("key directory must not be a symlink")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	return OpenFiles(dir)
}
func parseKey(cipher []byte, password string) (*age.X25519Identity, error) {
	i, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	i.SetMaxWorkFactor(20)
	raw, err := Decrypt(cipher, i)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	key, err := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("invalid env2 private key")
	}
	return key, nil
}
func LoadKey(dir, password string) (*age.X25519Identity, error) {
	f, err := keyFiles(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, exists, err := f.Read(KeyName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no key: run env2 init or env2 key import BACKUP")
	}
	if err := f.root.Chmod(KeyName, 0600); err != nil {
		return nil, err
	}
	return parseKey(data, password)
}
func CreateKey(dir, password string) (*age.X25519Identity, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("use a passphrase of at least 12 bytes")
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	data, err := Encrypt([]byte(key.String()+"\n"), recipient)
	if err != nil {
		return nil, err
	}
	f, err := keyFiles(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err = f.Write(KeyName, data, nil, false, 0600); err != nil {
		return nil, err
	}
	return key, nil
}
func ExportKey(dir, dest, password string) error {
	if _, err := LoadKey(dir, password); err != nil {
		return err
	}
	src, err := OpenFiles(dir)
	if err != nil {
		return err
	}
	defer src.Close()
	data, _, err := src.Read(KeyName)
	if err != nil {
		return err
	}
	dst, err := OpenFiles(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer dst.Close()
	return dst.Write(filepath.Base(dest), data, nil, false, 0600)
}
func ImportKey(dir, source, password string) error {
	src, err := OpenFiles(filepath.Dir(source))
	if err != nil {
		return err
	}
	defer src.Close()
	data, exists, err := src.Read(filepath.Base(source))
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("backup not found")
	}
	if _, err = parseKey(data, password); err != nil {
		return err
	}
	dst, err := keyFiles(dir)
	if err != nil {
		return err
	}
	defer dst.Close()
	return dst.Write(KeyName, data, nil, false, 0600)
}
