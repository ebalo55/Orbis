#!/bin/bash
# Plugin signing tool
# Generates key pairs and signs plugins with Ed25519

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Plugin Signing Tool"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  generate-key [label]      Generate a new Ed25519 key pair"
    echo "  sign <plugin> <key-file>  Sign a plugin with a private key"
    echo "  verify <plugin> <pubkey>  Verify a plugin signature"
    echo "  list-keys                 List all stored keys"
    echo ""
    echo "Examples:"
    echo "  $0 generate-key official"
    echo "  $0 sign target/debug/libmyplugin.so keys/official.key"
    echo "  $0 verify target/debug/libmyplugin.so a1b2c3d4..."
    exit 1
}

generate_key() {
    local label="${1:-default}"
    local keys_dir="${PROJECT_DIR}/keys"
    mkdir -p "$keys_dir"

    local private_key_file="${keys_dir}/${label}.key"
    local public_key_file="${keys_dir}/${label}.pub"

    if [ -f "$private_key_file" ]; then
        echo -e "${RED}Error: Key already exists: ${private_key_file}${NC}"
        echo "Please choose a different label or delete the existing key."
        exit 1
    fi

    echo -e "${YELLOW}Generating Ed25519 key pair for: ${label}${NC}"

    # Use a Rust program to generate keys
    cd "$PROJECT_DIR"
    cargo run --bin keygen -- "$private_key_file" "$public_key_file" "$label"

    echo -e "${GREEN}✓ Key pair generated:${NC}"
    echo "  Private key: ${private_key_file}"
    echo "  Public key:  ${public_key_file}"
    echo ""
    echo -e "${RED}⚠️  IMPORTANT: Keep the private key secret!${NC}"
    echo "  Add the public key to your hardcoded_public_keys in main.rs"
}

sign_plugin() {
    local plugin_file="$1"
    local key_file="$2"

    if [ ! -f "$plugin_file" ]; then
        echo -e "${RED}Error: Plugin file not found: ${plugin_file}${NC}"
        exit 1
    fi

    if [ ! -f "$key_file" ]; then
        echo -e "${RED}Error: Key file not found: ${key_file}${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Signing plugin: ${plugin_file}${NC}"

    # Use a Rust program to sign
    cd "$PROJECT_DIR"
    cargo run --bin plugin-signer -- sign "$plugin_file" "$key_file"

    echo -e "${GREEN}✓ Plugin signed successfully${NC}"
}

verify_signature() {
    local plugin_file="$1"
    local pubkey_hex="$2"

    if [ ! -f "$plugin_file" ]; then
        echo -e "${RED}Error: Plugin file not found: ${plugin_file}${NC}"
        exit 1
    fi

    echo -e "${YELLOW}Verifying plugin: ${plugin_file}${NC}"

    # Use a Rust program to verify
    cd "$PROJECT_DIR"
    cargo run --bin plugin-signer -- verify "$plugin_file" "$pubkey_hex"
}

list_keys() {
    local keys_dir="${PROJECT_DIR}/keys"

    if [ ! -d "$keys_dir" ]; then
        echo "No keys directory found."
        exit 0
    fi

    echo "Stored keys:"
    echo ""

    for pubkey_file in "$keys_dir"/*.pub; do
        if [ -f "$pubkey_file" ]; then
            local label=$(basename "$pubkey_file" .pub)
            local pubkey=$(cat "$pubkey_file")
            echo "  ${label}:"
            echo "    ${pubkey}"
            echo ""
        fi
    done
}

# Main
case "${1:-}" in
    generate-key)
        generate_key "$2"
        ;;
    sign)
        sign_plugin "$2" "$3"
        ;;
    verify)
        verify_signature "$2" "$3"
        ;;
    list-keys)
        list_keys
        ;;
    *)
        usage
        ;;
esac

