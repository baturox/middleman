#!/bin/sh
# Run ONCE, by the maintainer, on a trusted machine: makes the self-signed code-signing
# certificate the release workflow signs the macOS binaries with, and prints the two
# `gh secret set` commands that hand it to CI.
#
#   sh scripts/make-signing-cert.sh [OUTPUT_DIR]     (default: ./middleman-signing)
#
# Output (OUTPUT_DIR, mode 0700): middleman-signing.p12 (password-protected key + cert),
# middleman-signing.p12.b64 (the same, base64, for the secret), middleman-signing.crt and
# designated-requirement.txt (public). The private key and the password are never printed;
# the password is written to OUTPUT_DIR/p12-password (0600) so you can paste it into
# `gh secret set MACOS_SIGNING_PASSWORD` and then store it in your password manager.
# Delete OUTPUT_DIR afterwards (keep an offline backup of the .p12 and its password: a new
# certificate means a new designated requirement).
#
# What this buys: every release carries the same identifier and certificate, so the
# designated requirement is stable across releases. What it does not: Gatekeeper still treats
# the binary as not notarized (that needs a paid Apple Developer ID), and the Keychain still
# keys non-Developer-ID code by its cdhash in an item's partition list (see README, Upgrading).
set -eu

main() {
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
  out="${1:-./middleman-signing}"
  if [ -e "$out" ]; then
    echo "$out already exists; refusing to overwrite it" >&2
    exit 1
  fi
  umask 077
  mkdir -p "$out"
  chmod 700 "$out"

  cn="middleman release signing"
  cat > "$out/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = middleman release signing
O = middleman
[ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
EOF

  # key and cert: RSA 3072, 10 years
  openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
    -config "$out/openssl.cnf" \
    -keyout "$out/key.pem" -out "$out/middleman-signing.crt" 2>/dev/null

  # a random password, never echoed
  openssl rand -base64 33 | tr -d '\n=/+' > "$out/p12-password"
  chmod 600 "$out/p12-password"

  # macOS `security import` reads legacy PKCS#12 (3DES/SHA1) most reliably
  legacy=""
  if openssl version | grep -q '^OpenSSL 3'; then legacy="-legacy"; fi
  # shellcheck disable=SC2086
  openssl pkcs12 -export $legacy -name "$cn" \
    -inkey "$out/key.pem" -in "$out/middleman-signing.crt" \
    -out "$out/middleman-signing.p12" -passout "file:$out/p12-password"
  rm -f "$out/key.pem" "$out/openssl.cnf"
  base64 < "$out/middleman-signing.p12" | tr -d '\n' > "$out/middleman-signing.p12.b64"

  # the leaf hash the designated requirement pins (SHA-1 of the DER certificate)
  leaf=$(openssl x509 -in "$out/middleman-signing.crt" -outform DER | openssl dgst -sha1 | awk '{print $NF}')
  printf 'identifier "dev.baturox.middleman" and certificate leaf = H"%s"\n' "$leaf" \
    > "$out/designated-requirement.txt"

  echo "Created $out (mode 0700):"
  echo "  middleman-signing.p12      password-protected key + certificate (secret)"
  echo "  middleman-signing.p12.b64  the same, base64 (secret)"
  echo "  p12-password               its password (secret, 0600)"
  echo "  middleman-signing.crt      public certificate"
  echo "  designated-requirement.txt identifier \"dev.baturox.middleman\" and certificate leaf = H\"$leaf\""
  echo
  echo "Now hand it to GitHub Actions (run in the repository checkout):"
  echo
  echo "  gh secret set MACOS_SIGNING_P12 < $out/middleman-signing.p12.b64"
  echo "  gh secret set MACOS_SIGNING_PASSWORD < $out/p12-password"
  echo
  echo "Then keep the .p12 and its password offline (password manager) and delete $out."
}

main "$@"
