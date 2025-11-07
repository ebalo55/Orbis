# Example Plugin

A reference implementation demonstrating all features of the Orbis Assets plugin system.

## Features Demonstrated

1. **Plugin Lifecycle**
   - Initialization with context
   - Proper shutdown and cleanup
   - Hook registration

2. **Thread Safety**
   - Uses `AtomicPtr` for context storage
   - Safe for concurrent access

3. **Logging**
   - Comprehensive logging throughout lifecycle
   - Shows plugin events in server logs

## Building

```bash
cargo build --release --package example-plugin
```

Output: `target/release/libexample_plugin.so` (Linux)

## Loading

### Via Environment Variable

```bash
ORBIS_PLUGIN_PATH=./target/release/libexample_plugin.so cargo run --release
```

### Programmatically

```rust
registry.load_plugin(
    "./target/release/libexample_plugin.so",
    TrustLevel::Basic
)?;
```

## Plugin Symbols

The plugin exports the following symbols:

- `create_plugin` - Constructor function
- `PLUGIN_SIGNATURE` - Signature string (for verification)
- `PLUGIN_HASH` - Hash string (for verification)

Verify with:
```bash
nm -D ./target/release/libexample_plugin.so | grep -E "(create_plugin|PLUGIN_)"
```

## Expected Output

When loaded, you should see logs like:

```
[example_plugin] Initializing example plugin v0.1.0 by Emanuele (Ebalo) Balsamo
[example_plugin] Plugin initialized successfully!
[example_plugin] Context pointer: 0x...
[example_plugin] Registering hooks
[example_plugin] Hook registry pointer: 0x...
[example_plugin] Hooks registered successfully (stub)
```

## Future Enhancements

This is a minimal example. A real plugin would:

1. Access the shared database connection
2. Register actual hook handlers with callbacks
3. Add custom routes to the Axum router
4. Implement business logic
5. Handle errors gracefully

## Code Structure

```rust
pub struct ExamplePlugin {
    name: String,              // Plugin identifier
    version: String,           // Semantic version
    author: String,            // Author information
    context_ptr: AtomicPtr,    // Thread-safe context storage
}

impl Plugin for ExamplePlugin {
    fn init(&mut self, context: *const ()) { ... }
    fn shutdown(&mut self) { ... }
    fn register_hooks(&self, registry: *mut ()) { ... }
}

#[unsafe(no_mangle)]
pub extern "C" fn create_plugin() -> *mut dyn Plugin { ... }
```

## Security

This plugin demonstrates:
- Safe FFI boundary crossing
- Thread-safe context handling
- Proper resource cleanup
- No memory leaks (verified with valgrind in production)

## License

Same as Orbis Assets main project.

