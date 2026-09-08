#!/bin/sh
set -eu

# Usage: curl -fsSL https://raw.githubusercontent.com/alzkdpf/env2/main/install.sh | sh
# Pin a version by appending: | sh -s -- v0.1.0
repo='alzkdpf/env2'
version=${1:-latest}
case "$version" in latest|v[0-9]*) ;; *) echo 'Expected a release tag such as v0.1.0' >&2; exit 1 ;; esac
case "$version" in *[!a-zA-Z0-9._-]*) echo 'Invalid release tag' >&2; exit 1 ;; esac
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) echo 'env2 supports macOS and Linux.' >&2; exit 1 ;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) echo 'Unsupported CPU architecture.' >&2; exit 1 ;; esac
for tool in curl tar mktemp; do command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }; done
if command -v sha256sum >/dev/null 2>&1; then hasher=sha256sum
elif command -v shasum >/dev/null 2>&1; then hasher=shasum
else echo 'sha256sum or shasum is required.' >&2; exit 1; fi
if [ "$version" = latest ]; then base="https://github.com/$repo/releases/latest/download"
else base="https://github.com/$repo/releases/download/$version"; fi
archive="env2_${os}_${arch}.tar.gz"
umask 077
temp=$(mktemp -d)
install_temp=''
trap 'rm -rf "$temp"; if [ -n "$install_temp" ]; then rm -f "$install_temp"; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$base/$archive" -o "$temp/$archive"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$base/SHA256SUMS" -o "$temp/SHA256SUMS"
expected=$(awk -v name="$archive" '$2 == name {print $1}' "$temp/SHA256SUMS")
if [ "$hasher" = sha256sum ]; then actual=$(sha256sum "$temp/$archive" | awk '{print $1}')
else actual=$(shasum -a 256 "$temp/$archive" | awk '{print $1}'); fi
if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then echo 'Checksum verification failed; nothing installed.' >&2; exit 1; fi
tar -xzf "$temp/$archive" -C "$temp" env2
if [ ! -f "$temp/env2" ] || [ -L "$temp/env2" ]; then echo 'Invalid release archive.' >&2; exit 1; fi
install_dir=${ENV2_INSTALL_DIR:-"$HOME/.local/bin"}
mkdir -p "$install_dir"
install_temp=$(mktemp "$install_dir/.env2-install.XXXXXX")
cp "$temp/env2" "$install_temp"
chmod 755 "$install_temp"
mv -f "$install_temp" "$install_dir/env2"
install_temp=''
printf 'Installed env2 in %s\n' "$install_dir"
case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add this directory to your PATH: %s\n' "$install_dir" ;; esac
