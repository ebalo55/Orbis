use sea_orm::{DatabaseConnection};
use plugin_api::{make_plugin};

make_plugin!({
    plugin_name: Example,
    name:    "example_plugin",
    version: "0.1.0",
    author:  "Emanuele (Ebalo) Balsamo",
    init(&mut self, context: &mut PluginContext) -> Result<(), plugin_api::PluginError> {
        // access the context safely and ping the database
        let database = context.get::<DatabaseConnection>(plugin_api::ContextKey::Predefined(plugin_api::PredefinedContextKey::DatabaseConnection))?;

        if database.ping().await.is_ok() {
            tracing::info!("[{}] Successfully connected to the database!", self.name);
        } else {
            tracing::error!("[{}] Failed to connect to the database!", self.name);
        }

        Ok(())
    }
    shutdown(&mut self) -> Result<(), plugin_api::PluginError> {
        Ok(())
    }
    register_hooks(&self, hook_registry: *mut ()) -> Result<(), plugin_api::PluginError> {
        tracing::info!("[{}] Registering hooks", self.name);

        // In a real implementation, you would:
        // 1. Cast the hook_registry pointer to the actual type
        // 2. Register your hooks with different priorities
        // 3. Provide callbacks that will be executed by the host

        // This is a simplified example
        tracing::info!("[{}] Hook registry pointer: {:p}", self.name, hook_registry);
        tracing::info!("[{}] Hooks registered successfully (stub)", self.name);

        Ok(())
    }
});


/// Optional: Plugin signature for verification (example)
#[unsafe(no_mangle)]
pub static PLUGIN_SIGNATURE: &str = "example_plugin_signature_v1";

/// Optional: Plugin hash for verification (example)
#[unsafe(no_mangle)]
pub static PLUGIN_HASH: &str = "example_hash";
