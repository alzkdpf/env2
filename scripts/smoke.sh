#!/bin/sh
set -eu
binary=${1:?Usage: scripts/smoke.sh /absolute/path/to/env2}
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/project"
git -C "$temp/project" init -q
# This passphrase and file are disposable test fixtures, never real secrets.
pass='env2-integration-test-passphrase'
run() { printf '%s\n' "$pass" | "$binary" --key-dir "$temp/keys" --dir "$temp/project" --password-stdin "$@"; }
run init
printf 'TOKEN="fixture-only"\n# bytes preserved\n' > "$temp/project/.env"
cp "$temp/project/.env" "$temp/original"
run sync
cp "$temp/project/.env.enc" "$temp/first.enc"
run sync
cmp "$temp/first.enc" "$temp/project/.env.enc"
rm "$temp/project/.env"
run sync
cmp "$temp/original" "$temp/project/.env"
printf 'TOKEN=changed\n' > "$temp/project/.env"
if run sync; then echo 'Conflict was incorrectly accepted' >&2; exit 1; fi
run --force decrypt .env.enc
cmp "$temp/original" "$temp/project/.env"
run key export "$temp/backup.age"
printf '%s\n' "$pass" | "$binary" --key-dir "$temp/restored" --password-stdin key import "$temp/backup.age"
rm "$temp/project/.env"
printf '%s\n' "$pass" | "$binary" --key-dir "$temp/restored" --dir "$temp/project" --password-stdin sync
cmp "$temp/original" "$temp/project/.env"
if printf 'incorrect\n' | "$binary" --key-dir "$temp/keys" --password-stdin status; then echo 'Wrong password accepted' >&2; exit 1; fi
git -C "$temp/project" add .
if git -C "$temp/project" ls-files --error-unmatch .env >/dev/null 2>&1; then echo 'Plaintext staged' >&2; exit 1; fi
git -C "$temp/project" ls-files --error-unmatch .env.enc >/dev/null
printf 'CLI smoke passed: round trip, conflict, backup/restore, wrong password, Git staging.\n'
