#!/usr/bin/env sh
# This script generates a self-signed SSL certificate using OpenSSL.
# Usage: ./make-self-signed-cert.sh <output-directory> <common-name eg. example.com>
set -e
OUTPUT_DIR=$1
COMMON_NAME=$2

if [ -z "$OUTPUT_DIR" ] || [ -z "$COMMON_NAME" ]; then
  echo "Usage: $0 <output-directory> <common-name eg. example.com>"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout "$OUTPUT_DIR/self-signed.key" \
  -out "$OUTPUT_DIR/self-signed.crt" \
  -subj "/CN=$COMMON_NAME"