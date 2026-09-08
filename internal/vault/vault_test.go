package vault

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func fixture(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init", "-q", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git: %s %v", out, err)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func put(t *testing.T, e *Engine, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.Files.Dir, path), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, e *Engine, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.Files.Dir, path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestRoundTripGitAndIdempotence(t *testing.T) {
	e := fixture(t)
	original := []byte("# preserve formatting\r\nTOKEN='secret=abc'\r\nEMPTY=\r\nMULTI=\"a\nb\"\n")
	put(t, e, ".env.local", original)
	item := e.Inspect(".env.local")
	if item.State != Plain {
		t.Fatal(item)
	}
	if err := e.Apply(item, "encrypt", false); err != nil {
		t.Fatal(err)
	}
	cipher := read(t, e, ".env.local.enc")
	if bytes.Contains(cipher, []byte("secret=abc")) {
		t.Fatal("plaintext leaked")
	}
	item = e.Inspect(".env.local")
	if item.State != Same {
		t.Fatal(item)
	}
	if err := e.Apply(item, "encrypt", false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cipher, read(t, e, ".env.local.enc")) {
		t.Fatal("unchanged ciphertext rewritten")
	}
	if err := os.Remove(filepath.Join(e.Files.Dir, ".env.local")); err != nil {
		t.Fatal(err)
	}
	item = e.Inspect(".env.local")
	if item.State != Sealed {
		t.Fatal(item)
	}
	if err := e.Apply(item, "decrypt", false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, read(t, e, ".env.local")) {
		t.Fatal("bytes changed")
	}
	info, _ := os.Stat(filepath.Join(e.Files.Dir, ".env.local"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("plaintext permissions")
	}
	out, err := git(e.Files.Dir, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("?? .env.local\n")) || !bytes.Contains(out, []byte("?? .env.local.enc")) {
		t.Fatalf("unexpected Git status %s", out)
	}
}
func TestConflictAndStaleSnapshot(t *testing.T) {
	e := fixture(t)
	put(t, e, ".env", []byte("A=1"))
	if err := e.Apply(e.Inspect(".env"), "encrypt", false); err != nil {
		t.Fatal(err)
	}
	before := read(t, e, ".env.enc")
	put(t, e, ".env", []byte("A=2"))
	item := e.Inspect(".env")
	if item.State != Conflict {
		t.Fatal(item)
	}
	for _, action := range []string{"encrypt", "decrypt"} {
		if err := e.Apply(item, action, false); err == nil {
			t.Fatal("conflict allowed")
		}
	}
	if !bytes.Equal(before, read(t, e, ".env.enc")) || string(read(t, e, ".env")) != "A=2" {
		t.Fatal("conflict changed files")
	}
	put(t, e, ".env", []byte("A=3"))
	if err := e.Apply(item, "decrypt", true); err == nil {
		t.Fatal("stale write allowed")
	}
	if err := e.Apply(e.Inspect(".env"), "decrypt", true); err != nil {
		t.Fatal(err)
	}
	if string(read(t, e, ".env")) != "A=1" {
		t.Fatal("explicit direction failed")
	}
}
func TestWrongKeyTamperingAndSymlinks(t *testing.T) {
	e := fixture(t)
	put(t, e, ".env", []byte("A=keep"))
	if err := e.Apply(e.Inspect(".env"), "encrypt", false); err != nil {
		t.Fatal(err)
	}
	cipher := read(t, e, ".env.enc")
	other, _ := age.GenerateX25519Identity()
	if _, err := Decrypt(cipher, other); err == nil {
		t.Fatal("wrong key accepted")
	}
	put(t, e, ".env.enc", cipher[:len(cipher)/2])
	if err := e.Apply(e.Inspect(".env"), "decrypt", true); err == nil {
		t.Fatal("tampering accepted")
	}
	if string(read(t, e, ".env")) != "A=keep" {
		t.Fatal("failed decryption changed plaintext")
	}
	external := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(external, []byte("untouched"), 0600)
	if err := os.Symlink(external, filepath.Join(e.Files.Dir, "other.env")); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(e.Inspect("other.env"), "encrypt", true); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := e.Apply(e.Inspect("../outside.env"), "encrypt", true); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := os.Symlink(filepath.Dir(external), filepath.Join(e.Files.Dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(e.Inspect("linked/.env"), "encrypt", true); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}
func TestTrackedPlaintextRefused(t *testing.T) {
	e := fixture(t)
	put(t, e, ".env", []byte("A=1"))
	if _, err := git(e.Files.Dir, "add", ".env"); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(e.Inspect(".env"), "encrypt", false); err == nil {
		t.Fatal("tracked plaintext accepted")
	}
	if _, err := os.Stat(filepath.Join(e.Files.Dir, ".env.enc")); !os.IsNotExist(err) {
		t.Fatal("unexpected output")
	}
}
func TestDiscoveryAndIgnoredParent(t *testing.T) {
	e := fixture(t)
	for _, dir := range []string{"apps", "node_modules", ".env2"} {
		os.Mkdir(filepath.Join(e.Files.Dir, dir), 0700)
	}
	for _, name := range []string{".env", "apps/api.env.production", ".env.example", ".env.sample", "file.environment", "node_modules/.env", ".env2/.env"} {
		put(t, e, name, []byte("A=1"))
	}
	list, err := e.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("unexpected scan: %v", list)
	}
	put(t, e, ".gitignore", []byte("apps/\n"))
	if err := e.Apply(e.Inspect("apps/api.env.production"), "encrypt", false); err == nil {
		t.Fatal("ignored ciphertext allowed")
	}
}
func TestGitignoreSpecialNamesAndNoRewrite(t *testing.T) {
	e := fixture(t)
	path := "a [b]!.env.local"
	put(t, e, path, []byte("A=1"))
	put(t, e, ".gitignore", []byte("*.enc\n"))
	if err := e.Apply(e.Inspect(path), "encrypt", false); err != nil {
		t.Fatal(err)
	}
	before := read(t, e, ".gitignore")
	if err := e.Apply(e.Inspect(path), "encrypt", false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, read(t, e, ".gitignore")) {
		t.Fatal("ignore rules duplicated")
	}
}
func TestKeyBackupRestoreAndPassword(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	password := "test-only-passphrase-123"
	key, err := CreateKey(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateKey(dir, password); err == nil {
		t.Fatal("key overwritten")
	}
	if _, err := LoadKey(dir, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	loaded, err := LoadKey(dir, password)
	if err != nil || loaded.String() != key.String() {
		t.Fatal("load failed", err)
	}
	backup := filepath.Join(t.TempDir(), "backup.age")
	if err := ExportKey(dir, backup, password); err != nil {
		t.Fatal(err)
	}
	if err := ExportKey(dir, backup, password); err == nil {
		t.Fatal("backup overwritten")
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err := ImportKey(restored, backup, password); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey(restored, password)
	if err != nil || got.String() != key.String() {
		t.Fatal("restore failed", err)
	}
	for _, p := range []string{filepath.Join(dir, KeyName), backup} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("insecure permissions", p)
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("key directory permissions")
	}
}
