use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub https_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub static_path: PathBuf,
    pub opts: ConfigOpts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOpts {
    pub ip: String,
    pub port: u16,
    pub domain: String,
    pub email: Option<String>,
    pub https_dns: bool,
    pub development: bool,
    pub dns_lookup_max_attempts: Option<u32>,
    pub dns_lookup_delay_seconds: Option<u64>,
    pub storage_type: Option<String>,
    pub redis_url: Option<String>,
    pub lock_ttl_seconds: Option<u64>,
    pub redis_ssl: Option<RedisSslConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub acme: AcmeConfig,
    pub domains: crate::domain_reader::DomainSourceConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub ip: String,
    pub port: u16,
    /// Run as daemon (background process)
    #[serde(default)]
    pub daemon: bool,
    /// PID file path (for daemon mode)
    pub pid_file: Option<String>,
    /// Working directory for daemon
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Logging output: "stdout", "syslog", or "journald"
    #[serde(default = "default_log_output")]
    pub output: String,
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Syslog facility (for syslog output)
    #[serde(default = "default_syslog_facility")]
    pub syslog_facility: String,
    /// Syslog identifier/tag (for syslog output)
    #[serde(default = "default_syslog_identifier")]
    pub syslog_identifier: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            output: default_log_output(),
            level: default_log_level(),
            syslog_facility: default_syslog_facility(),
            syslog_identifier: default_syslog_identifier(),
        }
    }
}

fn default_log_output() -> String {
    "stdout".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_syslog_facility() -> String {
    "daemon".to_string()
}

fn default_syslog_identifier() -> String {
    "ssl-storage".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(rename = "type")]
    pub storage_type: String,
    pub https_path: String,
    pub redis_url: Option<String>,
    #[serde(default = "default_lock_ttl_seconds")]
    pub lock_ttl_seconds: u64,
    /// Redis SSL/TLS configuration
    #[serde(default)]
    pub redis_ssl: Option<RedisSslConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisSslConfig {
    /// Path to CA certificate file (PEM format)
    pub ca_cert_path: Option<String>,
    /// Path to client certificate file (PEM format, optional)
    pub client_cert_path: Option<String>,
    /// Path to client private key file (PEM format, optional)
    pub client_key_path: Option<String>,
    /// Skip certificate verification (for testing with self-signed certs)
    #[serde(default)]
    pub insecure: bool,
}

fn default_lock_ttl_seconds() -> u64 {
    900 // 15 minutes default
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub email: String,
    pub development: bool,
    #[serde(default = "default_dns_lookup_config")]
    pub dns_lookup: DnsLookupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_delay_seconds")]
    pub delay_seconds: u64,
}

fn default_dns_lookup_config() -> DnsLookupConfig {
    DnsLookupConfig {
        max_attempts: default_max_attempts(),
        delay_seconds: default_delay_seconds(),
    }
}

fn default_max_attempts() -> u32 {
    100
}

fn default_delay_seconds() -> u64 {
    10
}

impl AppConfig {
    /// Load configuration from YAML file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        use std::fs;
        let content = fs::read_to_string(path)
            .with_context(|| "Failed to read config file")?;
        let config: AppConfig = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse config YAML")?;
        Ok(config)
    }

    /// Create a domain-specific Config from AppConfig and DomainConfig
    pub fn create_domain_config(&self, domain: &crate::domain_reader::DomainConfig, https_path: PathBuf) -> Config {
        let mut domain_https_path = https_path.clone();
        domain_https_path.push(&domain.domain);

        let mut cert_path = domain_https_path.clone();
        cert_path.push("cert.pem");
        let mut key_path = domain_https_path.clone();
        key_path.push("key.pem");
        let static_path = domain_https_path.clone();

        Config {
            https_path: domain_https_path,
            cert_path,
            key_path,
            static_path,
            opts: ConfigOpts {
                ip: self.server.ip.clone(),
                port: self.server.port,
                domain: domain.domain.clone(),
                email: domain.email.clone().or_else(|| Some(self.acme.email.clone())),
                https_dns: domain.dns,
                development: self.acme.development,
                dns_lookup_max_attempts: Some(self.acme.dns_lookup.max_attempts),
                dns_lookup_delay_seconds: Some(self.acme.dns_lookup.delay_seconds),
                storage_type: Some(self.storage.storage_type.clone()),
                redis_url: self.storage.redis_url.clone(),
                lock_ttl_seconds: Some(self.storage.lock_ttl_seconds),
                redis_ssl: self.storage.redis_ssl.clone(),
            },
        }
    }
}


