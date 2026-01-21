use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;

/// Application configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub webauthn: WebAuthnConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    #[serde(default = "default_jwt_secret")]
    pub secret: String,
    #[serde(default)]
    pub previous_secrets: Vec<String>,
    #[serde(default = "default_access_token_expire")]
    pub access_token_expire_minutes: u64,
    #[serde(default = "default_refresh_token_expire")]
    pub refresh_token_expire_days: u64,
    #[serde(default)]
    pub cookie_secure: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_local_path")]
    pub local_path: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebAuthnConfig {
    #[serde(default = "default_rp_id")]
    pub rp_id: String,
    #[serde(default = "default_rp_name")]
    pub rp_name: String,
    #[serde(default = "default_rp_origin")]
    pub rp_origin: String,
}

// Default values
fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    1309
}

fn default_db_path() -> String {
    "data/cloudraver.db".to_string()
}

fn default_jwt_secret() -> String {
    // Generate a random secret if not configured
    "your-super-secret-key-change-it".to_string()
}

fn default_access_token_expire() -> u64 {
    15 // 15 minutes
}

fn default_refresh_token_expire() -> u64 {
    7 // 7 days
}

fn default_local_path() -> String {
    "data/uploads".to_string()
}

fn default_rp_id() -> String {
    "localhost".to_string()
}

fn default_rp_name() -> String {
    "CloudRaver".to_string()
}

fn default_rp_origin() -> String {
    "http://localhost:3000".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: default_jwt_secret(),
            previous_secrets: Vec::new(),
            access_token_expire_minutes: default_access_token_expire(),
            refresh_token_expire_days: default_refresh_token_expire(),
            cookie_secure: false,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            local_path: default_local_path(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            jwt: JwtConfig::default(),
            storage: StorageConfig::default(),
            webauthn: WebAuthnConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file and environment variables
    pub fn load() -> anyhow::Result<Self> {
        let mut config = Self::load_from_file()?;
        config.apply_env_overrides();
        config.ensure_directories()?;
        config.ensure_jwt_secret()?;
        config.ensure_webauthn_defaults();
        tracing::info!(
            "WebAuthn config: rp_id={}, rp_origin={}, rp_name={}",
            config.webauthn.rp_id,
            config.webauthn.rp_origin,
            config.webauthn.rp_name
        );
        Ok(config)
    }

    /// Ensure JWT secret is secure and persisted
    fn ensure_jwt_secret(&mut self) -> anyhow::Result<()> {
        // If secret is the default one or empty
        if self.jwt.secret == default_jwt_secret() || self.jwt.secret.is_empty() {
            let secret_path = Path::new("data/.jwt_secret");
            
            if secret_path.exists() {
                // Load existing secret
                let secret = fs::read_to_string(secret_path)?;
                self.jwt.secret = secret.trim().to_string();
                tracing::info!("Loaded persisted JWT secret from data/.jwt_secret");
            } else {
                // Generate new strong secret
                let secret = uuid::Uuid::new_v4().to_string();
                
                // Ensure data directory exists
                if let Some(parent) = secret_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                // Save to file
                fs::write(secret_path, &secret)?;
                self.jwt.secret = secret;
                tracing::info!("Generated and persisted new JWT secret to data/.jwt_secret");
            }
        }
        Ok(())
    }

    /// Load configuration from conf.ini or config.toml
    fn load_from_file() -> anyhow::Result<Self> {
        let config_paths = ["conf.ini", "config.toml", "data/conf.ini", "data/config.toml"];

        for path in config_paths {
            if Path::new(path).exists() {
                let content = fs::read_to_string(path)?;
                let config: Config = toml::from_str(&content)?;
                tracing::info!("Loaded configuration from {}", path);
                return Ok(config);
            }
        }

        tracing::info!("No configuration file found, using defaults");
        Ok(Config::default())
    }

    /// Apply environment variable overrides
    /// Format: CR_CONF_<SECTION>_<KEY>
    fn apply_env_overrides(&mut self) {
        // Server overrides
        if let Ok(val) = env::var("CR_CONF_SERVER_HOST") {
            self.server.host = val;
        }
        if let Ok(val) = env::var("CR_CONF_SERVER_PORT") {
            if let Ok(port) = val.parse() {
                self.server.port = port;
            }
        }

        // Database overrides
        if let Ok(val) = env::var("CR_CONF_DATABASE_PATH") {
            self.database.path = val;
        }

        // JWT overrides
        if let Ok(val) = env::var("CR_CONF_JWT_SECRET") {
            self.jwt.secret = val;
        }
        if let Ok(val) = env::var("CR_CONF_JWT_PREVIOUS_SECRETS") {
            self.jwt.previous_secrets = val
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
        }
        if let Ok(val) = env::var("CR_CONF_JWT_ACCESS_EXPIRE") {
            if let Ok(minutes) = val.parse() {
                self.jwt.access_token_expire_minutes = minutes;
            }
        }
        if let Ok(val) = env::var("CR_CONF_JWT_REFRESH_EXPIRE") {
            if let Ok(days) = val.parse() {
                self.jwt.refresh_token_expire_days = days;
            }
        }
        if let Ok(val) = env::var("CR_CONF_JWT_COOKIE_SECURE") {
            if let Ok(v) = val.parse() {
                self.jwt.cookie_secure = v;
            }
        }

        // Storage overrides
        if let Ok(val) = env::var("CR_CONF_STORAGE_LOCAL_PATH") {
            self.storage.local_path = val;
        }

        // WebAuthn overrides
        if let Ok(val) = env::var("CR_CONF_WEBAUTHN_RP_ID") {
            if !val.trim().is_empty() {
                self.webauthn.rp_id = val;
            }
        }
        if let Ok(val) = env::var("CR_CONF_WEBAUTHN_RP_NAME") {
            if !val.trim().is_empty() {
                self.webauthn.rp_name = val;
            }
        }
        if let Ok(val) = env::var("CR_CONF_WEBAUTHN_RP_ORIGIN") {
            if !val.trim().is_empty() {
                self.webauthn.rp_origin = val;
            }
        }
    }

    fn ensure_webauthn_defaults(&mut self) {
        if self.webauthn.rp_id.trim().is_empty() {
            self.webauthn.rp_id = default_rp_id();
        }
        if self.webauthn.rp_name.trim().is_empty() {
            self.webauthn.rp_name = default_rp_name();
        }
        if self.webauthn.rp_origin.trim().is_empty() {
            self.webauthn.rp_origin = default_rp_origin();
        }
    }

    /// Ensure required directories exist
    fn ensure_directories(&self) -> anyhow::Result<()> {
        // Ensure database directory exists
        if let Some(parent) = Path::new(&self.database.path).parent() {
            fs::create_dir_all(parent)?;
        }

        // Ensure local storage directory exists
        fs::create_dir_all(&self.storage.local_path)?;

        Ok(())
    }
}
