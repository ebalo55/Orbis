/// Plugin Worker Process
///
/// This binary runs as a separate process for each plugin, providing isolation
/// and communicating with the main server via IPC.
use anyhow::{Context, Result};
use clap::Parser;
use plugin_api::ipc::{IpcChannel, IpcConfig, IpcMessage};
use std::path::PathBuf;
use tracing::{error, info, warn};

mod worker;
use worker::PluginWorker;

#[derive(Parser, Debug)]
#[command(author, version, about = "Orbis Assets Plugin Worker Process", long_about = None)]
struct Args {
    /// Path to the plugin shared library (.so, .dll, .dylib)
    #[arg(short, long)]
    plugin: PathBuf,

    /// IPC endpoint (Unix socket path or Windows pipe name)
    #[arg(short, long)]
    endpoint: String,

    /// Plugin name
    #[arg(short, long)]
    name: String,

    /// Timeout for IPC operations in milliseconds
    #[arg(short, long, default_value = "5000")]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "plugin_worker=info".into()),
        )
        .init();

    // Parse arguments
    let args = Args::parse();

    info!(
        "Plugin worker starting: plugin={}, endpoint={}",
        args.plugin.display(),
        args.endpoint
    );

    // Verify plugin exists
    if !args.plugin.exists() {
        error!("Plugin file not found: {}", args.plugin.display());
        return Err(anyhow::anyhow!("Plugin file not found"));
    }

    // Run worker
    match run_worker(args).await {
        Ok(()) => {
            info!("Plugin worker exiting normally");
            Ok(())
        }
        Err(e) => {
            error!("Plugin worker error: {}", e);
            Err(e)
        }
    }
}

async fn run_worker(args: Args) -> Result<()> {
    // Create IPC config
    let ipc_config = IpcConfig {
        timeout_ms: args.timeout,
        ..Default::default()
    };

    // Connect to server
    info!("Connecting to server at {}", args.endpoint);
    let mut channel = IpcChannel::connect(&args.endpoint, ipc_config)
        .await
        .context("Failed to connect to server")?;

    info!("Connected to server");

    // Create plugin worker
    let mut worker = PluginWorker::new(args.plugin, args.name)?;

    // Main message loop
    loop {
        // Receive message from server
        let message = match channel.recv().await {
            Ok(msg) => msg,
            Err(plugin_api::ipc::IpcError::ConnectionClosed) => {
                info!("Server closed connection");
                break;
            }
            Err(e) => {
                error!("IPC receive error: {}", e);
                return Err(e.into());
            }
        };

        // Handle message
        let response = worker.handle_message(message).await?;

        // Send response if any
        if let Some(resp) = response {
            channel.send(&resp).await.context("Failed to send response")?;
        }

        // Check if we should exit
        if worker.should_exit() {
            info!("Worker shutting down");
            break;
        }
    }

    Ok(())
}

