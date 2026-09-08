#!/bin/sh
set -eu
version=${1:?Usage: scripts/release.sh v0.1.0}
mkdir -p dist
for os in darwin linux; do
  for arch in amd64 arm64; do
    build_dir=$(mktemp -d)
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w -X main.version=$version" -o "$build_dir/env2" ./cmd/env2
    tar -czf "dist/env2_${os}_${arch}.tar.gz" -C "$build_dir" env2
    rm -rf "$build_dir"
  done
done
(cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum env2_*.tar.gz; else shasum -a 256 env2_*.tar.gz; fi) > dist/SHA256SUMS
