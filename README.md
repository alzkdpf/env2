# env2

A small terminal UI for keeping environment files encrypted in Git.

**Unlock once → review file pairs → encrypt or decrypt → commit `.enc` files.**

`env2` runs locally. There is no account, hosted vault, or runtime service.

## Install

macOS and Linux, Apple Silicon/ARM64 and Intel/AMD64:

```sh
curl -fsSL https://raw.githubusercontent.com/alzkdpf/env2/main/install.sh | sh
```

The installer downloads a GitHub Release, checks its SHA-256 checksum, and installs
one executable in `~/.local/bin`. No sudo or Go installation is required.
If necessary, add `export PATH="$HOME/.local/bin:$PATH"` to your shell configuration.

Pin both the installer and binary version:

```sh
curl -fsSL https://raw.githubusercontent.com/alzkdpf/env2/v0.1.1/install.sh | sh -s -- v0.1.1
```

Review `install.sh` before executing it if your environment requires script review.
Override the install directory with `ENV2_INSTALL_DIR` on the `sh` side of the pipe.

## Start

```sh
cd your-project
env2
```

On first launch, choose and confirm a strong passphrase (at least 12 bytes).
Your private key is generated locally and stored, encrypted with the passphrase, at:

```text
~/.env2/env2.age
```

Subsequent launches ask for the passphrase to unlock that key.
The passphrase is not an account password and is not uploaded anywhere.

```text
  env2  /  local secrets, ready for Git
  /your-project

> [x] plaintext only      .env
  [x] encrypted only     apps/web/.env.local
  [ ] different          apps/api/.env
  [ ] in sync            .env.production

  ↑↓ move · Space select · A select new · Enter auto
  E encrypt · D decrypt · R refresh · Q quit
```

Press Enter for an unambiguous operation. Review the action list and press Y to apply.
For different file pairs, explicitly choose E (plaintext wins) or D (encrypted file wins).
No values are displayed. The selected files' `.gitignore` rules are updated automatically.

```sh
git add .env.enc .gitignore
git commit -m "Update encrypted environment"
```

Commit the corresponding `.gitignore` changes for nested files too. `env2` never commits
or pushes automatically. Plaintext remains on your computer after encryption.

## File rules

| Plaintext | Encrypted sibling |
| --- | --- |
| `.env` | `.env.enc` |
| `.env.local` | `.env.local.enc` |
| `api.env.production` | `api.env.production.enc` |

Search starts in the current directory and descends into subdirectories. Names must
contain `.env` followed by a dot or the end of the name. `.env.example`, `.env.sample`,
`.env.template` and their dotted variants are excluded. `.git`, `.env2`, `node_modules`,
`vendor`, `.venv`, `dist`, `build`, symlinks and non-regular files are skipped.

- Plaintext only: encrypt.
- Encrypted only: decrypt.
- Both, same bytes: do not rewrite the ciphertext.
- Both, different bytes: require an explicit direction.
- Wrong key, invalid or damaged ciphertext: stop; preserve the existing destination.

Original bytes, comments, ordering, quotes and line endings are preserved. Files are
limited to 16 MiB of plaintext. Modification times are not used to choose a winner.

Git is required for write operations. Already tracked plaintext is refused. Review the
file and use `git rm --cached -- path/to/.env` to stop tracking it before retrying.
The tool also refuses output that would remain ignored by Git, including ignored parent
folders. Fix those rules yourself, then retry. Existing Git history is not rewritten.

## Key backup and moving computers

**Back up your encrypted key. The passphrase alone cannot recover your files.**

```sh
env2 key export /safe/offline/location/env2-key.age
```

On another computer, install env2, clone the repository, copy your encrypted key backup
through a trusted channel, and run:

```sh
env2 key import /safe/location/env2-key.age
env2
```

Export and import ask for the backup's passphrase and never overwrite an existing file
or key. Store the backup outside Git. Every project using the same local key shares its
access scope. This first version is intended for personal use or deliberately shared
keys, not per-person team authorization. Per-project keys are possible with `--key-dir`.

## CLI and automation

Flags precede the command. Paths are relative to `--dir` (the current directory by default).

```sh
env2 init
env2 status
env2 sync
env2 encrypt .env apps/api/.env.local
env2 decrypt .env.enc
env2 --force encrypt .env        # explicitly replace different encrypted contents
env2 --force decrypt .env.enc    # explicitly replace different local plaintext
env2 --dir ./apps/web status
env2 --key-dir /safe/project-keys status
env2 --version
```

`sync` first checks every pair for conflicts and decryption errors. File operations are
performed sequentially; if a later Git or filesystem check fails, earlier successful
operations remain applied and the command reports the failure. It is not a batch transaction.

For automation, `--password-stdin` reads a single passphrase line from standard input.
Provide it through your CI secret mechanism or a protected pipe, never a literal in a
committed script or command-line argument. Provision the encrypted key separately; a
passphrase alone is insufficient. Noninteractive commands return a nonzero exit code on error.

## Security model and limits

- Standard [age](https://github.com/FiloSottile/age) ASCII-armored ciphertext; native X25519
  recipients for files, age's scrypt passphrase mode for the private key. No custom cipher.
- Key directory permissions: `0700`; encrypted key, backups and restored plaintext: `0600`.
- Decryption must finish authenticating before output is written. Temporary files are
  private and a same-directory rename replaces an existing destination.
- Paths are confined with Go's `os.Root`. Symlinks are refused. Files changed since the
  scan are refused. This is not a lock against a malicious local process or a transaction
  coordinating other editors; avoid concurrent external writes while applying operations.
- The unlocked key and file contents exist in process memory. Go does not guarantee
  complete secret erasure. An unlocked machine, malware, swap, crash dumps and terminal
  compromise are outside this tool's protection.
- Whole-file encryption hides variable names and values, but filenames and approximate
  size remain visible. Git cannot meaningfully merge encrypted contents. Resolve conflicts
  by decrypting the versions separately; do not merge the ciphertext text.
- Re-encryption cannot revoke copies of old ciphertext or a stolen key. Rotate actual
  service credentials after a leak. Key rotation and passphrase changes have no built-in
  command in v0.1.1. There is no independent security audit yet.
- Published checksums detect corruption; they do not independently authenticate a
  compromised GitHub account or installer. No signing or provenance claim is made.

## Development

Go 1.27.1 or newer and Git:

```sh
go test -race ./...
go vet ./...
go build -o ./env2 ./cmd/env2
sh scripts/smoke.sh "$PWD/env2"
```

The TUI uses [Bubble Tea](https://github.com/charmbracelet/bubbletea).
Unit tests cover encryption, tampering, conflicts, stale reads, symlink refusal, Git rules,
backup/restore, permissions and TUI confirmation. The smoke test runs the real CLI in a
disposable project. CI runs on macOS and Linux. Tagged releases build four standalone binaries.

## License

MIT. See [LICENSE](LICENSE).
