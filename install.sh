#!/bin/sh
# middleman installer: downloads the latest (or $MIDDLEMAN_VERSION) release binary for this
# machine, verifies its SHA-256, and installs it to $MIDDLEMAN_INSTALL_DIR (default ~/.local/bin).
#
#   curl -fsSL https://raw.githubusercontent.com/baturox/middleman/main/install.sh | sh
#   MIDDLEMAN_VERSION=v0.1.0 MIDDLEMAN_INSTALL_DIR=/usr/local/bin sh install.sh
set -eu

REPO="baturox/middleman"
DIR="${MIDDLEMAN_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s); arch=$(uname -m)
case "$os" in
  Darwin) os=apple-darwin ;;
  Linux)  os=unknown-linux-gnu ;;
  *) echo "unsupported OS: $os (Windows: download the .zip from the Releases page)" >&2; exit 1 ;;
esac
case "$arch" in
  arm64|aarch64) arch=aarch64 ;;
  x86_64|amd64)  arch=x86_64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
target="$arch-$os"

if [ -n "${MIDDLEMAN_VERSION:-}" ]; then
  tag="$MIDDLEMAN_VERSION"
else
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$tag" ] || { echo "could not determine latest release" >&2; exit 1; }
fi

name="middleman-$tag-$target"
url="https://github.com/$REPO/releases/download/$tag/$name.tar.gz"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "→ downloading $name"
curl -fsSL "$url" -o "$tmp/$name.tar.gz"
curl -fsSL "$url.sha256" -o "$tmp/$name.tar.gz.sha256" 2>/dev/null || \
  curl -fsSL "https://github.com/$REPO/releases/download/$tag/SHA256SUMS.txt" | grep "$name.tar.gz" > "$tmp/$name.tar.gz.sha256"

echo "→ verifying checksum"
expected=$(awk '{print $1}' "$tmp/$name.tar.gz.sha256")
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp/$name.tar.gz" | awk '{print $1}')
else actual=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}'); fi
[ "$expected" = "$actual" ] || { echo "checksum mismatch" >&2; exit 1; }

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$DIR"
install -m 0755 "$tmp/$name/middleman" "$DIR/middleman"
[ "$os" = apple-darwin ] && xattr -d com.apple.quarantine "$DIR/middleman" 2>/dev/null || true

echo "✓ installed middleman $tag to $DIR/middleman"
case ":$PATH:" in *":$DIR:"*) ;; *) echo "  add to PATH:  export PATH=\"$DIR:\$PATH\"" ;; esac
echo "  next:  middleman init && middleman doctor"
