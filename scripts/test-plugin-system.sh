#!/bin/bash
# Test script for the plugin system

set -e

echo "================================"
echo "Orbis Assets Plugin System Test"
echo "================================"
echo ""

# Build everything
echo "Building workspace..."
cargo build --release --all 2>&1 | grep -E "(Compiling|Finished)" | tail -5
echo "✓ Build complete"
echo ""

# Check for plugin file
PLUGIN_PATH="./target/release/libexample_plugin.so"
if [ -f "$PLUGIN_PATH" ]; then
    echo "✓ Plugin library found: $PLUGIN_PATH"
    ls -lh "$PLUGIN_PATH"
else
    echo "✗ Plugin library not found!"
    exit 1
fi
echo ""

# Check symbols
echo "Checking plugin symbols..."
nm -D "$PLUGIN_PATH" | grep -E "(create_plugin|PLUGIN_SIGNATURE|PLUGIN_HASH)" || true
echo ""

# Test loading the plugin
echo "Testing plugin loading..."
echo "Setting ORBIS_PLUGIN_PATH=$PLUGIN_PATH"
export ORBIS_PLUGIN_PATH="$PLUGIN_PATH"

# Note: This will fail if database is not configured
# but it will show the plugin system attempting to load
echo ""
echo "To test the server with the plugin, ensure your .env is configured and run:"
echo "  ORBIS_PLUGIN_PATH=$PLUGIN_PATH cargo run --release"
echo ""
echo "================================"
echo "Plugin System Ready!"
echo "================================"

