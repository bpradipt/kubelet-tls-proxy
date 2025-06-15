#!/bin/bash

set -e

CERT_DIR="$1"

if [ -z "$CERT_DIR" ]; then
  echo "Usage: $0 <cert-dir>"
  exit 1
fi

mkdir -p "$CERT_DIR"

# CA
openssl genrsa -out "$CERT_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 365 -out "$CERT_DIR/ca.crt" -subj "/CN=test-ca"

# kubelet server cert (used by proxy to impersonate kubelet)
openssl genrsa -out "$CERT_DIR/tls.key" 2048
openssl req -new -key "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.csr" -subj "/CN=localhost"
openssl x509 -req -in "$CERT_DIR/tls.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/tls.crt" -days 365 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost")

# client cert (used by proxy to connect to kubelet)
openssl genrsa -out "$CERT_DIR/client.key" 2048
openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" -subj "/CN=proxy-client"
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/client.crt" -days 365 -sha256
