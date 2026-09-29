#!/bin/sh
set -eu

enabled=$(printf '%s' "${XRAY_HYSTERIA2_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
[ "$enabled" = true ] || exit 0

mode=${XRAY_HYSTERIA2_TLS_MODE:-legacy}
mkdir -p /target
staging=$(mktemp -d /target/.hysteria-tls.XXXXXX)
ca_dir=
cleanup() {
  rm -rf "$staging"
  if [ -n "$ca_dir" ]; then rm -rf "$ca_dir"; fi
}
trap cleanup EXIT

case "$mode" in
  self-signed)
    cert_ip=${XRAY_HYSTERIA2_CERT_IP:-}
    if ! printf '%s\n' "$cert_ip" | awk -F. '
      NF != 4 { exit 1 }
      { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i ~ /^0[0-9]+$/ || $i > 255 || $i < 0) exit 1 }
    '; then
      echo 'XRAY_HYSTERIA2_CERT_IP must be an IPv4 address in self-signed mode' >&2
      exit 1
    fi
    if [ -s /target/fullchain.pem ] && [ -s /target/privkey.pem ] &&
       [ "$(cat /target/.mode 2>/dev/null || true)" = "self-signed:$cert_ip" ] &&
       openssl x509 -in /target/fullchain.pem -noout -checkend 2592000 >/dev/null 2>&1 &&
       openssl x509 -in /target/fullchain.pem -noout -checkip "$cert_ip" >/dev/null 2>&1; then
      echo "Reusing the existing mkcert certificate for $cert_ip"
      exit 0
    fi
    # Do not install mkcert's local CA in the container trust store. The CA
    # private key is temporary; clients use insecure=1 in this mode.
    ca_dir=$(mktemp -d /tmp/.mkcert-ca.XXXXXX)
    export CAROOT="$ca_dir"
    mkcert -cert-file "$staging/leaf.pem" -key-file "$staging/privkey.pem" "$cert_ip"
    cat "$staging/leaf.pem" "$CAROOT/rootCA.pem" > "$staging/fullchain.pem"
    printf 'self-signed:%s\n' "$cert_ip" > "$staging/.mode"
    ;;
  custom|legacy)
    test -s /source/fullchain.pem || { echo 'missing secrets/hysteria/fullchain.pem' >&2; exit 1; }
    test -s /source/privkey.pem || { echo 'missing secrets/hysteria/privkey.pem' >&2; exit 1; }
    cp /source/fullchain.pem "$staging/fullchain.pem"
    cp /source/privkey.pem "$staging/privkey.pem"
    printf '%s\n' "$mode" > "$staging/.mode"
    ;;
  *)
    echo 'XRAY_HYSTERIA2_TLS_MODE must be self-signed or custom' >&2
    exit 1
    ;;
esac

openssl x509 -in "$staging/fullchain.pem" -noout -checkend 0 >/dev/null || {
  echo 'Hysteria 2 certificate is invalid or expired' >&2
  exit 1
}
openssl x509 -in "$staging/fullchain.pem" -pubkey -noout > "$staging/cert.pub"
openssl pkey -in "$staging/privkey.pem" -pubout > "$staging/key.pub"
cmp -s "$staging/cert.pub" "$staging/key.pub" || {
  echo 'Hysteria 2 certificate and private key do not match' >&2
  exit 1
}
if [ "$mode" != self-signed ] && [ -n "${XRAY_HYSTERIA2_TLS_SERVER_NAME:-}" ]; then
  case "$XRAY_HYSTERIA2_TLS_SERVER_NAME" in
    *[!0-9.]* ) openssl x509 -in "$staging/fullchain.pem" -noout -checkhost "$XRAY_HYSTERIA2_TLS_SERVER_NAME" >/dev/null ;;
    * ) openssl x509 -in "$staging/fullchain.pem" -noout -checkip "$XRAY_HYSTERIA2_TLS_SERVER_NAME" >/dev/null ;;
  esac || {
    echo 'Hysteria 2 certificate does not cover XRAY_HYSTERIA2_TLS_SERVER_NAME' >&2
    exit 1
  }
fi

install -m 0444 -o 10001 -g 10001 "$staging/fullchain.pem" "$staging/ready-fullchain.pem"
install -m 0400 -o 10001 -g 10001 "$staging/privkey.pem" "$staging/ready-privkey.pem"
mv "$staging/ready-fullchain.pem" /target/fullchain.pem
mv "$staging/ready-privkey.pem" /target/privkey.pem
mv "$staging/.mode" /target/.mode
echo "Prepared Hysteria 2 TLS certificate ($mode)"
