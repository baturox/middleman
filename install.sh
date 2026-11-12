#!/bin/sh
# middleman installer: downloads the latest (or $MIDDLEMAN_VERSION) release binary for this
# machine, verifies its SHA-256 (fail-closed), verifies the GitHub build-provenance
# attestation when `gh` is installed and logged in (a failed verification is fatal), and
# installs it to $MIDDLEMAN_INSTALL_DIR
# (default ~/.local/bin). Over an existing install it upgrades: the old binary is kept as
# middleman.prev (`middleman upgrade --rollback` restores it) and, when Claude Code is wired
# to middleman, `middleman setup claude --refresh --yes` updates that wiring
# (MIDDLEMAN_NO_WIRING=1 skips it). Installed copies can also upgrade themselves:
# `middleman upgrade`. Quiet by default (about three lines); MIDDLEMAN_VERBOSE=1 shows every
# step.
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

say() { [ "${MIDDLEMAN_VERBOSE:-0}" = 1 ] && echo "$@"; return 0; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

main() {
  DIR="${MIDDLEMAN_INSTALL_DIR:-$HOME/.local/bin}"
  V=""; [ "${MIDDLEMAN_VERBOSE:-0}" = 1 ] && V="--verbose"

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

  existing=""
  if [ -x "$DIR/middleman" ]; then
    existing=$("$DIR/middleman" --version 2>/dev/null | awk 'NR==1 {print $2}') || existing=""
    case "$existing" in
      "" | *[!A-Za-z0-9.+-]*) existing="unknown" ;;
    esac
    if [ "v$existing" = "$tag" ] && [ "${MIDDLEMAN_FORCE:-0}" != 1 ]; then
      echo "✓ middleman ${tag#v} is already installed ($DIR/middleman; MIDDLEMAN_FORCE=1 reinstalls)"
      return 0
    fi
    say "-> upgrading v$existing → $tag ($DIR/middleman)"
  fi

  name="middleman-$tag-$target"
  url="https://github.com/$REPO/releases/download/$tag/$name.tar.gz"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

  say "-> downloading $name"
  fetch "$url" "$tmp/$name.tar.gz"
  if ! fetch "$url.sha256" "$tmp/$name.tar.gz.sha256" 2>/dev/null; then
    fetch "https://github.com/$REPO/releases/download/$tag/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt"
    grep " $name.tar.gz\$" "$tmp/SHA256SUMS.txt" > "$tmp/$name.tar.gz.sha256" || true
  fi

  expected=$(awk 'NR==1 {print $1}' "$tmp/$name.tar.gz.sha256")
  actual=$(sha256_of "$tmp/$name.tar.gz")
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "checksum missing or mismatched; refusing to install" >&2
    exit 1
  fi
  say "   checksum ok (sha256 $actual)"

  # provenance: only a verification gh actually ran and failed is reported (and fatal)
  if ! command -v gh >/dev/null 2>&1; then
    say "   build provenance not checked (the GitHub CLI is not installed)"
    need_att
  elif ! gh auth status >/dev/null 2>&1; then
    say "   build provenance not checked (gh is not logged in)"
    need_att
  elif gh attestation verify "$tmp/$name.tar.gz" --repo "$REPO" >/dev/null 2>"$tmp/att.err"; then
    say "   provenance verified: built by $REPO's release workflow"
  elif grep -qiE "failed to get trusted root|unsupported tlog public key|sigstore verifier|unknown command .attestation.|tls handshake|no such host|i/o timeout" "$tmp/att.err"; then
    # gh could not run the check (e.g. too old for Sigstore's current keys): not evidence
    # against the file, whose checksum matched.
    say "   build provenance not checked (your GitHub CLI is too old: brew upgrade gh)"
    need_att
  else
    echo "error: build attestation verification failed for $name; refusing to install." >&2
    sed -n '1,3p' "$tmp/att.err" | sed 's/^/  gh: /' >&2
    exit 1
  fi

  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  got=$("$tmp/$name/middleman" --version 2>/dev/null | awk 'NR==1 {print $2}') || got=""
  if [ "v$got" != "$tag" ]; then
    echo "the downloaded binary does not report $tag; refusing to install" >&2
    exit 1
  fi
  mkdir -p "$DIR"
  if [ -n "$existing" ]; then
    cp -p "$DIR/middleman" "$DIR/middleman.prev"
    say "   the previous binary is kept as $DIR/middleman.prev (middleman upgrade --rollback restores it)"
  fi
  # write next to the target, then rename: the old binary is never half replaced (and a
  # running MCP server notices the new file and re-executes it)
  install -m 0755 "$tmp/$name/middleman" "$DIR/.middleman.new.$$"
  mv -f "$DIR/.middleman.new.$$" "$DIR/middleman"
  if [ "$os" = apple-darwin ]; then
    xattr -d com.apple.quarantine "$DIR/middleman" 2>/dev/null || true
    say "   note: the macOS binary is not notarized; the quarantine flag was removed so it can run."
    say "   Integrity rests on the checksum (and attestation) above."
  fi

  if [ -z "$existing" ]; then
    echo "✓ middleman ${tag#v} installed to $DIR/middleman (verified)"
    case ":$PATH:" in *":$DIR:"*) ;; *) echo "  add to PATH:  export PATH=\"$DIR:\$PATH\"" ;; esac
    echo "  next:  middleman init && middleman doctor"
    return 0
  fi
  echo "✓ middleman $existing → ${tag#v} (verified)"
  if [ "${MIDDLEMAN_NO_WIRING:-0}" != 1 ] &&
    grep -qsE 'route --hook|statusline|"middleman"' "$HOME/.claude/settings.json" "$HOME/.claude.json" .mcp.json .claude/settings.json; then
    # shellcheck disable=SC2086
    "$DIR/middleman" setup claude --refresh --yes $V ||
      echo "warning: the Claude Code settings refresh did not finish; run: middleman setup claude --refresh" >&2
  fi
  if [ "$os" = apple-darwin ] && keychain_prompt "$DIR/middleman.prev" "$DIR/middleman"; then
    echo "  macOS will ask once to let middleman use its Keychain key: click Always Allow"
  fi
  case ":$PATH:" in *":$DIR:"*) ;; *) echo "  add to PATH:  export PATH=\"$DIR:\$PATH\"" ;; esac
}

# MIDDLEMAN_REQUIRE_ATTESTATION=1: a check that could not run is fatal too
need_att() {
  if [ "${MIDDLEMAN_REQUIRE_ATTESTATION:-0}" = 1 ]; then
    echo "cannot verify the build attestation (gh missing or not logged in); refusing to install (MIDDLEMAN_REQUIRE_ATTESTATION=1)" >&2
    exit 1
  fi
}

# Will macOS ask before the new binary reads a key the old one stored? Only when a key is in
# the Keychain, and unless both binaries carry the same Developer-ID-anchored requirement:
# the Keychain partitions everything else by cdhash, which changes with each build.
keychain_prompt() { # keychain_prompt OLD NEW
  grep -qsE '^[[:space:]]*key_source[[:space:]]*=[[:space:]]*"keychain"' "$HOME/.config/middleman/config.toml" || return 1
  old_dr=$(codesign -d -r- "$1" 2>/dev/null | sed -n 's/^designated => //p')
  new_dr=$(codesign -d -r- "$2" 2>/dev/null | sed -n 's/^designated => //p')
  say "   designated requirement: old [$old_dr] new [$new_dr]"
  case "$new_dr" in
    *"anchor apple generic"*) [ "$old_dr" = "$new_dr" ] && return 1 ;;
  esac
  return 0
}

main "$@"
