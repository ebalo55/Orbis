#!/bin/bash
# Script to compute SHA-256 hashes of plugin .so files
# This should be run during the build process to generate trusted plugin hashes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TARGET_DIR="${PROJECT_DIR}/target"

# Determine build profile (debug or release)
PROFILE="${1:-debug}"

PLUGIN_DIR="${TARGET_DIR}/${PROFILE}"

echo "Computing plugin hashes for profile: ${PROFILE}"
echo "Plugin directory: ${PLUGIN_DIR}"
echo ""

# Find all .so files in the target directory
SO_FILES=$(find "${PLUGIN_DIR}" -maxdepth 1 -name "lib*.so" -type f 2>/dev/null || true)

if [ -z "$SO_FILES" ]; then
    echo "No plugin files found in ${PLUGIN_DIR}"
    exit 0
fi

echo "// Auto-generated trusted plugin entries"
echo "// Generated at: $(date)"
echo "// Profile: ${PROFILE}"
echo "// Using: SHA3-512 hashing"
echo "//"
echo "// Add this to your server initialization:"
echo "let hardcoded_trusted_plugins = vec!["

for so_file in $SO_FILES; do
    filename=$(basename "$so_file")
    # Use sha3sum if available, fallback to note about manual computation
    if command -v sha3sum &> /dev/null; then
        hash=$(sha3sum -a 512 "$so_file" | awk '{print $1}')
    else
        hash="COMPUTE_SHA3_512_MANUALLY"
        echo "    // WARNING: sha3sum not found, compute SHA3-512 manually for ${filename}" >&2
    fi

    # Extract version from filename if possible (e.g., libplugin-1.0.0.so)
    # This is a simple heuristic, adjust as needed
    version="1, 0, 0"  # Default version

    echo "    TrustedPluginEntry {"
    echo "        hash: \"${hash}\".to_string(),"
    echo "        version: PluginVersion::new(${version}),"
    echo "        note: Some(\"${filename}\".to_string()),"
    echo "    },"
done

echo "];"
echo ""
echo "// Individual plugin information:"
for so_file in $SO_FILES; do
    filename=$(basename "$so_file")
    if command -v sha3sum &> /dev/null; then
        hash=$(sha3sum -a 512 "$so_file" | awk '{print $1}')
        echo "// ${filename}:"
        echo "//   SHA3-512: ${hash}"
    else
        echo "// ${filename}: Compute SHA3-512 manually (sha3sum not available)"
    fi
done

echo ""
echo "// Note: Install sha3sum for automatic hash computation:"
echo "//   Ubuntu/Debian: sudo apt-get install libdigest-sha3-perl"
echo "//   Or use: echo 'text' | openssl dgst -sha3-512"

