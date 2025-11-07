/// Plugin Worker - handles plugin lifecycle and message processing
use anyhow::{Context, Result};
use plugin_api::ipc::{IpcMessage, protocol::{HookRegistration, LogLevel}};
use plugin_api::{Plugin, PluginError};
use std::path::PathBuf;
use tracing::{debug, error, info};

pub struct PluginWorker {
    plugin_path: PathBuf,
    plugin_name: String,
    plugin: Option<Box<dyn Plugin>>,
    library: Option<libloading::Library>,
    should_exit: bool,
}

impl PluginWorker {
    /// Create a new plugin worker
    pub fn new(plugin_path: PathBuf, plugin_name: String) -> Result<Self> {
        Ok(Self {
            plugin_path,
            plugin_name,
            plugin: None,
            library: None,
            should_exit: false,
        })
    }

    /// Load the plugin library
    fn load_plugin(&mut self) -> Result<()> {
        info!("Loading plugin from {}", self.plugin_path.display());

        // Load library
        let library = unsafe {
            libloading::Library::new(&self.plugin_path)
                .context("Failed to load plugin library")?
        };

        // Get constructor symbol
        let constructor: libloading::Symbol<unsafe extern "C" fn() -> *mut dyn Plugin> = unsafe {
            library
                .get(b"create_plugin")
                .context("Plugin does not export create_plugin symbol")?
        };

        // Create plugin instance
        let plugin_ptr = unsafe { constructor() };
        let plugin = unsafe { Box::from_raw(plugin_ptr) };

        info!(
            "Loaded plugin: {} v{} by {}",
            plugin.name(),
            plugin.version(),
            plugin.author()
        );

        self.plugin = Some(plugin);
        self.library = Some(library);

        Ok(())
    }

    /// Handle an IPC message
    pub async fn handle_message(&mut self, message: IpcMessage) -> Result<Option<IpcMessage>> {
        debug!("Handling message: {:?}", message);

        match message {
            IpcMessage::Initialize { context_data } => {
                self.handle_initialize(context_data).await
            }

            IpcMessage::ExecuteHook { hook_name, data, timeout_ms } => {
                self.handle_execute_hook(hook_name, data, timeout_ms).await
            }

            IpcMessage::RegisterHooksRequest => {
                self.handle_register_hooks().await
            }

            IpcMessage::Shutdown { grace_period_ms } => {
                self.handle_shutdown(grace_period_ms).await
            }

            IpcMessage::Ping => {
                Ok(Some(IpcMessage::Pong))
            }

            _ => {
                error!("Unexpected message type");
                Ok(None)
            }
        }
    }

    /// Handle initialization
    async fn handle_initialize(&mut self, _context_data: Vec<u8>) -> Result<Option<IpcMessage>> {
        // Load plugin if not already loaded
        if self.plugin.is_none() {
            if let Err(e) = self.load_plugin() {
                error!("Failed to load plugin: {}", e);
                return Ok(Some(IpcMessage::InitializeResponse {
                    success: false,
                    error: Some(format!("Failed to load plugin: {}", e)),
                }));
            }
        }

        // TODO: Deserialize context_data and pass to plugin
        // For now, pass null pointer (will be implemented in Phase 3)

        if let Some(plugin) = &mut self.plugin {
            match plugin.init(std::ptr::null()).await {
                Ok(()) => {
                    info!("Plugin initialized successfully");
                    Ok(Some(IpcMessage::InitializeResponse {
                        success: true,
                        error: None,
                    }))
                }
                Err(e) => {
                    error!("Plugin initialization failed: {}", e);
                    Ok(Some(IpcMessage::InitializeResponse {
                        success: false,
                        error: Some(format!("{}", e)),
                    }))
                }
            }
        } else {
            Ok(Some(IpcMessage::InitializeResponse {
                success: false,
                error: Some("Plugin not loaded".to_string()),
            }))
        }
    }

    /// Handle hook execution
    async fn handle_execute_hook(
        &mut self,
        hook_name: String,
        data: Vec<u8>,
        timeout_ms: u64,
    ) -> Result<Option<IpcMessage>> {
        // TODO: Implement actual hook execution with timeout
        // For now, just acknowledge

        info!("Executing hook: {} (timeout: {}ms)", hook_name, timeout_ms);

        Ok(Some(IpcMessage::HookResponse {
            result: Vec::new(), // Empty result for now
            error: None,
        }))
    }

    /// Handle hook registration request
    async fn handle_register_hooks(&mut self) -> Result<Option<IpcMessage>> {
        // TODO: Get actual hooks from plugin
        // For now, return empty list

        info!("Registering hooks");

        Ok(Some(IpcMessage::RegisterHooks {
            hooks: Vec::new(),
        }))
    }

    /// Handle shutdown
    async fn handle_shutdown(&mut self, grace_period_ms: u64) -> Result<Option<IpcMessage>> {
        info!("Shutting down (grace period: {}ms)", grace_period_ms);

        // Shutdown plugin if loaded
        if let Some(plugin) = &mut self.plugin {
            if let Err(e) = plugin.shutdown().await {
                error!("Plugin shutdown failed: {}", e);
            }
        }

        self.should_exit = true;

        Ok(Some(IpcMessage::ShutdownAck))
    }

    /// Check if worker should exit
    pub fn should_exit(&self) -> bool {
        self.should_exit
    }
}

impl Drop for PluginWorker {
    fn drop(&mut self) {
        info!("Plugin worker dropping");

        // Clean up plugin before library
        self.plugin = None;
        self.library = None;
    }
}

