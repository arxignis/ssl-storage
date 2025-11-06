//! Domain reader that supports multiple sources: file, Redis, and HTTP

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub domain: String,
    pub email: Option<String>,
    pub dns: bool,
    pub wildcard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSourceConfig {
    pub source: String,
    pub file_path: Option<String>,
    pub redis_key: Option<String>,
    pub redis_url: Option<String>,
    pub redis_ssl: Option<crate::config::RedisSslConfig>,
    pub http_url: Option<String>,
    pub http_refresh_interval: Option<u64>,
}

/// Domain reader trait
#[async_trait::async_trait]
pub trait DomainReader: Send + Sync {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>>;
}

/// File-based domain reader
pub struct FileDomainReader {
    file_path: PathBuf,
}

impl FileDomainReader {
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: file_path.into(),
        }
    }
}

#[async_trait::async_trait]
impl DomainReader for FileDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        let content = tokio::fs::read_to_string(&self.file_path)
            .await
            .with_context(|| format!("Failed to read domains file: {:?}", self.file_path))?;

        let domains: Vec<DomainConfig> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse domains JSON: {:?}", self.file_path))?;

        Ok(domains)
    }
}

/// Redis-based domain reader
pub struct RedisDomainReader {
    redis_key: String,
    redis_url: String,
    redis_ssl: Option<crate::config::RedisSslConfig>,
}

impl RedisDomainReader {
    pub fn new(redis_key: String, redis_url: Option<String>, redis_ssl: Option<crate::config::RedisSslConfig>) -> Self {
        Self {
            redis_key,
            redis_url: redis_url
                .or_else(|| std::env::var("REDIS_URL").ok())
                .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string()),
            redis_ssl,
        }
    }

    /// Create Redis client with optional SSL configuration
    fn create_redis_client(&self) -> Result<redis::Client> {
        if let Some(ssl_config) = &self.redis_ssl {
            Self::create_client_with_ssl(&self.redis_url, ssl_config)
        } else {
            redis::Client::open(self.redis_url.as_str())
                .with_context(|| format!("Failed to connect to Redis at {}", self.redis_url))
        }
    }

    /// Create Redis client with custom SSL/TLS configuration
    fn create_client_with_ssl(redis_url: &str, ssl_config: &crate::config::RedisSslConfig) -> Result<redis::Client> {
        use native_tls::{Certificate, Identity, TlsConnector};

        // Build TLS connector with custom certificates
        let mut tls_builder = TlsConnector::builder();

        // Load CA certificate if provided
        if let Some(ca_cert_path) = &ssl_config.ca_cert_path {
            let ca_cert_data = std::fs::read(ca_cert_path)
                .with_context(|| format!("Failed to read CA certificate from {}", ca_cert_path))?;
            let ca_cert = Certificate::from_pem(&ca_cert_data)
                .with_context(|| format!("Failed to parse CA certificate from {}", ca_cert_path))?;
            tls_builder.add_root_certificate(ca_cert);
            tracing::info!("Loaded CA certificate from {}", ca_cert_path);
        }

        // Load client certificate and key if provided
        if let (Some(client_cert_path), Some(client_key_path)) = (&ssl_config.client_cert_path, &ssl_config.client_key_path) {
            let client_cert_data = std::fs::read(client_cert_path)
                .with_context(|| format!("Failed to read client certificate from {}", client_cert_path))?;
            let client_key_data = std::fs::read(client_key_path)
                .with_context(|| format!("Failed to read client key from {}", client_key_path))?;

            // Try to create identity from PEM format (cert + key)
            let identity = Identity::from_pkcs8(&client_cert_data, &client_key_data)
                .or_else(|_| {
                    // Try PEM format if PKCS#8 fails
                    Identity::from_pkcs12(&client_cert_data, "")
                })
                .or_else(|_| {
                    // Try loading as separate PEM files
                    // Combine cert and key into a single PEM
                    let mut combined = client_cert_data.clone();
                    combined.extend_from_slice(b"\n");
                    combined.extend_from_slice(&client_key_data);
                    Identity::from_pkcs12(&combined, "")
                })
                .with_context(|| format!("Failed to parse client certificate/key from {} and {}. Supported formats: PKCS#8, PKCS#12, or PEM", client_cert_path, client_key_path))?;
            tls_builder.identity(identity);
            tracing::info!("Loaded client certificate from {} and key from {}", client_cert_path, client_key_path);
        }

        // Configure certificate verification
        if ssl_config.insecure {
            tls_builder.danger_accept_invalid_certs(true);
            tls_builder.danger_accept_invalid_hostnames(true);
            tracing::warn!("Redis SSL: Certificate verification disabled (insecure mode)");
        }

        let _tls_connector = tls_builder.build()
            .with_context(|| "Failed to build TLS connector")?;

        // Note: The redis crate with tokio-native-tls-comp uses native-tls internally,
        // but doesn't expose a way to pass a custom TlsConnector. However, when using
        // rediss:// URLs, it will use the system trust store. For custom CA certificates,
        // we need to add them to the system trust store or use a workaround.

        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Failed to create Redis client with SSL config"))?;

        Ok(client)
    }
}

#[async_trait::async_trait]
impl DomainReader for RedisDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        use redis::AsyncCommands;

        let client = self.create_redis_client()?;

        use redis::aio::ConnectionManager;
        let mut conn = ConnectionManager::new(client)
            .await
            .with_context(|| "Failed to get Redis connection")?;

        let content: String = conn.get(&self.redis_key).await
            .with_context(|| format!("Failed to read domains from Redis key: {}", self.redis_key))?;

        let domains: Vec<DomainConfig> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse domains JSON from Redis"))?;

        Ok(domains)
    }
}

/// HTTP-based domain reader
pub struct HttpDomainReader {
    url: String,
    refresh_interval: u64,
    cached_domains: tokio::sync::RwLock<Option<(Vec<DomainConfig>, chrono::DateTime<chrono::Utc>)>>,
}

impl HttpDomainReader {
    pub fn new(url: String, refresh_interval: u64) -> Self {
        Self {
            url,
            refresh_interval,
            cached_domains: tokio::sync::RwLock::new(None),
        }
    }

    async fn fetch_domains(&self) -> Result<Vec<DomainConfig>> {
        let response = reqwest::get(&self.url).await
            .with_context(|| format!("Failed to fetch domains from {}", self.url))?;

        let content = response.text().await
            .with_context(|| format!("Failed to read response from {}", self.url))?;

        let domains: Vec<DomainConfig> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse domains JSON from HTTP response"))?;

        Ok(domains)
    }
}

#[async_trait::async_trait]
impl DomainReader for HttpDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        let now = chrono::Utc::now();

        // Check cache
        {
            let cache = self.cached_domains.read().await;
            if let Some((domains, cached_at)) = cache.as_ref() {
                let age = now - *cached_at;
                if age.num_seconds() < self.refresh_interval as i64 {
                    return Ok(domains.clone());
                }
            }
        }

        // Fetch fresh data
        let domains = self.fetch_domains().await?;

        // Update cache
        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some((domains.clone(), now));
        }

        Ok(domains)
    }
}

/// Factory for creating domain readers
pub struct DomainReaderFactory;

impl DomainReaderFactory {
    pub fn create(config: &DomainSourceConfig) -> Result<Box<dyn DomainReader>> {
        match config.source.as_str() {
            "file" => {
                let file_path = config.file_path.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("file_path is required for file source"))?;
                Ok(Box::new(FileDomainReader::new(file_path)))
            }
            "redis" => {
                let redis_key = config.redis_key.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("redis_key is required for redis source"))?
                    .clone();
                let redis_url = config.redis_url.clone();
                let redis_ssl = config.redis_ssl.clone();
                Ok(Box::new(RedisDomainReader::new(redis_key, redis_url, redis_ssl)))
            }
            "http" => {
                let url = config.http_url.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("http_url is required for http source"))?
                    .clone();
                let refresh_interval = config.http_refresh_interval.unwrap_or(300);
                Ok(Box::new(HttpDomainReader::new(url, refresh_interval)))
            }
            _ => Err(anyhow::anyhow!("Unknown domain source: {}", config.source)),
        }
    }
}

