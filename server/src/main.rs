use axum::Json;
use axum::Router;
use axum::routing::get;
use num_traits::Unsigned;
use rustls_pemfile::{certs, pkcs8_private_keys};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use serde::{Deserialize, Serialize};

use std::{env, fs::File, io::BufReader, str::FromStr, sync::Arc, time::Duration};
use std::sync::RwLock;
use thiserror::Error;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::{ServerConfig, crypto};
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use plugin_api::{ContextKey, HookRegistry, PluginContext, PluginError, PluginLoader, PluginRegistry, PluginSecurity, PredefinedContextKey, SecurityPolicy, TrustLevel};
// Note: PluginVersion and TrustedPluginEntry used in comments for documentation

#[derive(Error, Debug)]
enum AppError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Invalid value for environment variable {0}: {1}")]
    InvalidEnvValue(String, String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    #[error("Server error: {0}")]
    ServerError(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    TlsError(String),

    #[error("Plugin error: {0}")]
    PluginError(#[from] PluginError),
}

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: String,
}

/// Parses an environment variable and converts it to the specified unsigned type T.
///
/// # Arguments
/// * `variable_name` - The name of the environment variable to parse.
///
/// # Returns
/// The parsed value of type T.
fn parse_env_var<T>(variable_name: &str) -> Result<T, AppError>
where
    T: Unsigned + FromStr,
    T::Err: std::fmt::Debug,
{
    let value =
        env::var(variable_name).map_err(|_| AppError::MissingEnvVar(variable_name.to_string()))?;

    value
        .parse::<T>()
        .map_err(|e| AppError::InvalidEnvValue(variable_name.to_string(), format!("{:?}", e)))
}

/// Initializes the database connection using environment variables for configuration.
///
/// # Returns
/// A Result containing the DatabaseConnection or a DbErr.
async fn init_db() -> Result<DatabaseConnection, AppError> {
    let db_url = env::var("ORBIS_DB_URL")
        .map_err(|_| AppError::MissingEnvVar("ORBIS_DB_URL".to_string()))?;

    let schema = env::var("ORBIS_DB_SCHEMA").unwrap_or_else(|_| "public".to_owned());

    let mut options = ConnectOptions::new(db_url);
    options
        .max_connections(parse_env_var("ORBIS_DB_MAX_CONNECTIONS")?)
        .min_connections(parse_env_var("ORBIS_DB_MIN_CONNECTIONS")?)
        .connect_timeout(Duration::from_millis(parse_env_var(
            "ORBIS_DB_CONNECT_TIMEOUT_MS",
        )?))
        .acquire_timeout(Duration::from_millis(parse_env_var(
            "ORBIS_DB_ACQUIRE_TIMEOUT_MS",
        )?))
        .idle_timeout(Duration::from_millis(parse_env_var(
            "ORBIS_DB_IDLE_TIMEOUT_MS",
        )?))
        .max_lifetime(Duration::from_millis(parse_env_var(
            "ORBIS_DB_MAX_LIFETIME_MS",
        )?))
        .set_schema_search_path(schema)
        .sqlx_logging(false)
        .test_before_acquire(true);

    Ok(Database::connect(options).await?)
}

/// Health check endpoint handler.
///
/// # Returns
/// A JSON response indicating the health status.
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "OK".to_owned(),
    })
}

/// Initializes tracing for logging.
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_env("ORBIS_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Loads plugins from a path. If the path is a directory, loads all .so files within it.
/// If the path is a file, loads only that plugin.
///
/// # Arguments
/// * `plugin_registry` - The plugin registry to load plugins into
/// * `path` - Path to a plugin file or directory containing plugins
async fn load_plugins(plugin_registry: &Arc<PluginRegistry>, path: &str) {
    use std::path::Path;

    let plugin_path = Path::new(path);

    // Check if path exists
    if !plugin_path.exists() {
        warn!("Plugin path '{}' does not exist, skipping plugin loading", path);
        return;
    }

    if plugin_path.is_dir() {
        info!("Loading plugins from directory: {}", path);

        // Read directory and load all .so files
        match std::fs::read_dir(plugin_path) {
            Ok(entries) => {
                let mut loaded_count = 0;
                let mut failed_count = 0;

                for entry in entries.flatten() {
                    let entry_path = entry.path();

                    // Only process .so files (Linux shared libraries)
                    if entry_path.is_file() &&
                       entry_path.extension()
                           .map_or(false, |ext| ext == "so" || ext == "dll" || ext == "dylib") {

                        info!("Loading plugin from: {}", entry_path.display());
                        match plugin_registry.load_plugin(&entry_path, TrustLevel::Trusted).await {
                            Ok(name) => {
                                info!("Successfully loaded plugin: {}", name);
                                loaded_count += 1;
                            }
                            Err(e) => {
                                warn!("Failed to load plugin from '{}': {}", entry_path.display(), e);
                                failed_count += 1;
                            }
                        }
                    }
                }

                info!("Plugin loading complete: {} loaded, {} failed", loaded_count, failed_count);
            }
            Err(e) => {
                warn!("Failed to read plugin directory '{}': {}", path, e);
            }
        }
    } else if plugin_path.is_file() {
        info!("Loading single plugin from: {}", path);
        match plugin_registry.load_plugin(plugin_path, TrustLevel::Trusted).await {
            Ok(name) => info!("Successfully loaded plugin: {}", name),
            Err(e) => warn!("Failed to load plugin from '{}': {}", path, e),
        }
    } else {
        warn!("Plugin path '{}' is neither a file nor a directory", path);
    }
}

/// Initializes SSL/TLS configuration if certificate and key paths are provided.
///
/// # Returns
/// An Option containing the ServerConfig if SSL is configured, or None if not.
fn init_ssl_config() -> Result<Option<Arc<ServerConfig>>, AppError> {
    let cert_path = env::var("ORBIS_TLS_CERT_PATH").ok();
    let key_path = env::var("ORBIS_TLS_KEY_PATH").ok();

    let _ = CryptoProvider::install_default(crypto::ring::default_provider())
        .map_err(|_e| AppError::TlsError("Failed to install crypto provider".to_owned()));

    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            info!("Loading TLS configuration");

            let cert_file = File::open(&cert_path).map_err(|e| {
                AppError::TlsError(format!(
                    "Failed to open certificate file {}: {}",
                    cert_path, e
                ))
            })?;
            let key_file = File::open(&key_path).map_err(|e| {
                AppError::TlsError(format!("Failed to open key file {}: {}", key_path, e))
            })?;

            let mut cert_reader = BufReader::new(cert_file);
            let mut key_reader = BufReader::new(key_file);

            let certs = certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AppError::TlsError(format!("Failed to parse certificate: {}", e)))?;

            let mut keys = pkcs8_private_keys(&mut key_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AppError::TlsError(format!("Failed to parse private key: {}", e)))?;

            if keys.is_empty() {
                return Err(AppError::TlsError(
                    "No private keys found in key file".to_string(),
                ));
            }

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, keys.remove(0).into())
                .map_err(|e| AppError::TlsError(format!("Failed to build TLS config: {}", e)))?;

            info!("TLS configuration loaded successfully");
            Ok(Some(Arc::new(config)))
        }
        (None, None) => {
            warn!("TLS not configured, running in HTTP mode");
            Ok(None)
        }
        (Some(_), None) => Err(AppError::TlsError(
            "ORBIS_TLS_CERT_PATH provided but ORBIS_TLS_KEY_PATH is missing".to_string(),
        )),
        (None, Some(_)) => Err(AppError::TlsError(
            "ORBIS_TLS_KEY_PATH provided but ORBIS_TLS_CERT_PATH is missing".to_string(),
        )),
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!("{}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), AppError> {
    #[cfg(feature = "dev")]
    dotenv::dotenv().ok();

    init_tracing();

    info!("Initializing database connection");
    let db = init_db().await?;
    info!("Database connection established");

    // Initialize plugin system
    info!("Initializing plugin system");
    let plugin_context = Arc::new(PluginContext::new());
    let hook_registry = Arc::new(RwLock::new(HookRegistry::new()));

    // Share database connection with plugins
    plugin_context.share(ContextKey::Predefined(PredefinedContextKey::DatabaseConnection), Arc::new(db.clone()))?;

    // Configure plugin security with hardcoded trusted plugin entries and public keys
    let security_policy = SecurityPolicy::default();

    // IMPORTANT: In production, these should be computed/generated during build time
    // TODO: Add build script to:
    //   1. Generate key pair for signing
    //   2. Sign all official plugins
    //   3. Compute plugin hashes
    //   4. Generate hardcoded entries with signatures
    
    // Hardcoded public keys for signature verification (official signing keys)
    let hardcoded_public_keys = vec![
        // Add official public keys here during build
        // Example:
        // PublicKey::from_hex("a1b2c3d4e5f6...").unwrap(),
    ];

    let hardcoded_trusted_plugins = vec![
        // Add trusted plugin entries here during build
        // Each entry MUST include a valid Ed25519 signature
        // Example:
        // TrustedPluginEntry {
        //     hash: "a1b2c3...".to_string(),  // SHA3-512 hash
        //     version: PluginVersion::new(1, 0, 0),
        //     signature: PluginSignature { /* from signing */ },
        //     note: Some("Official example plugin".to_string()),
        // },
    ];

    let plugin_security = Arc::new(PluginSecurity::new(
        security_policy,
        hardcoded_trusted_plugins,
        hardcoded_public_keys
    ));

    // Initialize plugin security (uses system keyring or Docker env vars automatically)
    plugin_security.initialize()?;

    let plugin_loader = Arc::new(PluginLoader::new(plugin_security.clone()));
    let plugin_registry = Arc::new(PluginRegistry::new(
        plugin_loader,
        plugin_context.clone(),
        hook_registry.clone(),
        plugin_security.clone(),
    ));

    // Scan for available plugins first
    let plugin_path = env::var("ORBIS_PLUGIN_PATH").unwrap_or_else(|_| "plugins".to_string());
    let scan_path = std::path::Path::new(&plugin_path);

    if scan_path.is_dir() {
        match plugin_registry.scan_directory(&plugin_path) {
            Ok(count) => info!("Scanned and discovered {} plugins", count),
            Err(e) => warn!("Failed to scan plugin directory: {}", e),
        }
    } else if scan_path.is_file() {
        match plugin_registry.discover_plugin(&plugin_path) {
            Ok(()) => info!("Discovered single plugin: {}", plugin_path),
            Err(e) => warn!("Failed to discover plugin: {}", e),
        }
    }

    // Load plugins from environment variable or default plugins folder
    load_plugins(&plugin_registry, &plugin_path).await;

    info!("Plugin system initialized with {} plugins", plugin_registry.plugin_count());

    // Start resource monitor for plugins
    let monitor_interval = env::var("ORBIS_PLUGIN_MONITOR_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs);

    let _monitor_handle = plugin_registry.clone().start_resource_monitor(monitor_interval);
    info!("Plugin resource monitor started");

    let app = Router::new()
        .route("/health", get(health_check));

    let addr = format!(
        "{}:{}",
        env::var("ORBIS_SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_owned()),
        env::var("ORBIS_SERVER_PORT").unwrap_or_else(|_| "8000".to_owned())
    );

    let tls_config = init_ssl_config()?;

    match tls_config {
        Some(config) => {
            info!("Starting HTTPS server at https://{}", addr);

            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(config);

            // Note: axum_server::bind_rustls requires the address to be in the format `IP:PORT`
            // The syntax `localhost:8000` is NOT supported for TLS binding.
            axum_server::bind_rustls(
                addr.parse().map_err(|e| {
                    AppError::InvalidEnvValue(
                        "ORBIS_SERVER_HOST/ORBIS_SERVER_PORT".to_owned(),
                        format!("{}", e),
                    )
                })?,
                rustls_config,
            )
            .serve(app.into_make_service())
            .await?;
        }
        None => {
            info!("Starting HTTP server at http://{}", addr);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    // Unload all plugins on shutdown
    plugin_registry.unload_all().await?;

    Ok(())
}
