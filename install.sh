#!/bin/sh
# middleman installer: downloads the latest (or $MIDDLEMAN_VERSION) release binary for this
# machine, verifies its SHA-256 (fail-closed), optionally verifies the GitHub build-provenance
# attestation when `gh` is installed, and installs it to $MIDDLEMAN_INSTALL_DIR
# (default ~/.local/bin).
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/baturox/middleman/main/install.sh | sh
#   MIDDLEMAN_VERSION=v0.1.0 MIDDLEMAN_INSTALL_DIR=/usr/local/bin sh install.sh
#
# Everything runs inside main(), called on the last line, so a truncated download executes
# nothing.
set -eu

REPO="baturox/middleman"

fetch() { # fetch URL [OUTFILE]
  if [ $# -ge 2 ]; then
    curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
  else
    curl --proto '=https' --tlsv1.2 -fsSL "$1"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

main() {
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
    tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$tag" ] || { echo "could not determine latest release" >&2; exit 1; }
  fi
  case "$tag" in
    *[!A-Za-z0-9._-]*) echo "refusing odd release tag: $tag" >&2; exit 1 ;;
  esac

  name="middleman-$tag-$target"
  url="https://github.com/$REPO/releases/download/$tag/$name.tar.gz"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

  echo "-> downloading $name"
  fetch "$url" "$tmp/$name.tar.gz"
  if ! fetch "$url.sha256" "$tmp/$name.tar.gz.sha256" 2>/dev/null; then
    fetch "https://github.com/$REPO/releases/download/$tag/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt"
    grep " $name.tar.gz\$" "$tmp/SHA256SUMS.txt" > "$tmp/$name.tar.gz.sha256" || true
  fi

  echo "-> verifying checksum"
  expected=$(awk 'NR==1 {print $1}' "$tmp/$name.tar.gz.sha256")
  actual=$(sha256_of "$tmp/$name.tar.gz")
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "checksum missing or mismatched; refusing to install" >&2
    exit 1
  fi

  if command -v gh >/dev/null 2>&1; then
    echo "-> verifying build provenance (gh attestation verify)"
    if gh attestation verify "$tmp/$name.tar.gz" --repo "$REPO" >/dev/null 2>&1; then
      echo "   provenance verified: built by $REPO's release workflow"
    elif [ "${MIDDLEMAN_REQUIRE_ATTESTATION:-0}" = 1 ]; then
      echo "attestation verification failed; refusing to install (MIDDLEMAN_REQUIRE_ATTESTATION=1)" >&2
      exit 1
    else
      echo "   warning: could not verify the attestation (not logged in to gh, or an older release)." >&2
      echo "   set MIDDLEMAN_REQUIRE_ATTESTATION=1 to make this fatal." >&2
    fi
  else
    echo "   (install the GitHub CLI to also verify build provenance: gh attestation verify)"
  fi

  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  mkdir -p "$DIR"
  install -m 0755 "$tmp/$name/middleman" "$DIR/middleman"
  if [ "$os" = apple-darwin ]; then
    xattr -d com.apple.quarantine "$DIR/middleman" 2>/dev/null || true
    echo "   note: the macOS binary is not code-signed or notarized; the quarantine flag was"
    echo "   removed so it can run. Integrity rests on the checksum (and attestation) above."
  fi

  echo "installed middleman $tag to $DIR/middleman"
  case ":$PATH:" in *":$DIR:"*) ;; *) echo "  add to PATH:  export PATH=\"$DIR:\$PATH\"" ;; esac
  echo "  next:  middleman init && middleman doctor"
}

main "$@"
