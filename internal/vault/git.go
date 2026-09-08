package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	return cmd.Output()
}
func (e *Engine) gitRoot() (string, bool, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", false, fmt.Errorf("git is required to check plaintext tracking")
	}
	out, err := git(e.Files.Dir, "rev-parse", "--show-toplevel")
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && bytes.Contains(exit.Stderr, []byte("not a git repository")) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("cannot inspect Git repository: %w", err)
	}
	return strings.TrimSpace(string(out)), true, nil
}
func ignoreLiteral(name string) string {
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune("\\*?[]#! ", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Place exact rules beside the file so parent wildcards cannot override them.
func (e *Engine) Protect(path string) error {
	if strings.ContainsAny(path, "\r\n") {
		return fmt.Errorf("newline in filename is unsupported")
	}
	root, repo, err := e.gitRoot()
	if err != nil {
		return err
	}
	var relative string
	if repo {
		relative, err = filepath.Rel(root, filepath.Join(e.Files.Dir, path))
		if err != nil {
			return err
		}
		out, err := git(root, "ls-files", "-z", "--", ":(literal)"+filepath.ToSlash(relative))
		if err != nil {
			return fmt.Errorf("cannot check tracked files: %w", err)
		}
		if len(out) > 0 {
			return fmt.Errorf("plaintext is tracked by Git: %q; untrack it with git rm --cached first", path)
		}
	}
	ignorePath := filepath.Join(filepath.Dir(path), ".gitignore")
	previous, exists, err := e.Files.Read(ignorePath)
	if err != nil {
		return err
	}
	plainRule := "/" + ignoreLiteral(filepath.Base(path))
	cipherRule := "!" + plainRule + ".enc"
	lines := strings.Split(string(previous), "\n")
	has := func(rule string) bool {
		for _, line := range lines {
			if line == rule {
				return true
			}
		}
		return false
	}
	next := append([]byte(nil), previous...)
	if !has(plainRule) || !has(cipherRule) {
		if len(next) > 0 && next[len(next)-1] != '\n' {
			next = append(next, '\n')
		}
		next = append(next, []byte("# env2: keep plaintext local; commit the encrypted sibling\n"+plainRule+"\n"+cipherRule+"\n")...)
		if err = e.Files.Write(ignorePath, next, previous, exists, 0644); err != nil {
			return err
		}
	}
	if !repo {
		return nil
	}
	// --no-index checks the ignore rules even for an already tracked ciphertext.
	check := func(p string) (bool, error) {
		_, err := git(root, "check-ignore", "--no-index", "-q", "--", filepath.ToSlash(p))
		if err == nil {
			return true, nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("cannot verify .gitignore: %w", err)
	}
	ignored, err := check(relative)
	if err != nil {
		return err
	}
	if !ignored {
		return fmt.Errorf("plaintext is not ignored; check Git ignore rules for %q", path)
	}
	ignored, err = check(relative + ".enc")
	if err != nil {
		return err
	}
	if ignored {
		return fmt.Errorf("encrypted file is ignored (possibly its parent directory); fix Git ignore rules for %q", path+".enc")
	}
	return nil
}
