//! Storage backend abstraction for certificate storage.
//! Supports multiple storage backends (file system, Redis, etc.)

mod file;
mod redis;

use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

pub use file::FileStorage;
pub use redis::RedisStorage;

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    /// File system storage
    File,
    /// Redis storage
    Redis,
}

/// Trait for certificate storage backends
#[async_trait]
pub trait Storage: Send + Sync {
    /// Read certificate from storage (from live directory)
    async fn read_cert(&self) -> Result<Vec<u8>>;

    /// Read certificate chain from storage (from live directory)
    async fn read_chain(&self) -> Result<Vec<u8>>;

    /// Read fullchain (cert + chain) from storage (from live directory)
    async fn read_fullchain(&self) -> Result<Vec<u8>>;

    /// Read private key from storage (from live directory)
    async fn read_key(&self) -> Result<Vec<u8>>;

    /// Write certificate, chain, and fullchain to storage (certbot-style)
    /// cert: The domain certificate
    /// chain: The intermediate certificate chain
    /// key: The private key
    async fn write_certs(&self, cert: &[u8], chain: &[u8], key: &[u8]) -> Result<()>;

    /// Check if certificate exists
    async fn cert_exists(&self) -> bool;

    /// Read certificate creation timestamp
    async fn read_created_at(&self) -> Result<chrono::DateTime<chrono::Utc>>;

    /// Write certificate creation timestamp
    async fn write_created_at(&self, created_at: chrono::DateTime<chrono::Utc>) -> Result<()>;

    /// Write challenge file for ACME HTTP-01 challenge
    async fn write_challenge(&self, token: &str, key_auth: &str) -> Result<()>;

    /// Write DNS challenge code for ACME DNS-01 challenge
    async fn write_dns_challenge(&self, domain: &str, dns_record: &str, dns_value: &str) -> Result<()>;

    /// Get the path for static files (well-known directory)
    fn static_path(&self) -> PathBuf;

    /// Read fullchain synchronously (for compatibility with sync APIs like rustls)
    /// Returns None if the storage backend doesn't support sync operations
    fn read_fullchain_sync(&self) -> Option<Result<Vec<u8>>> {
        None
    }

    /// Read private key synchronously (for compatibility with sync APIs like rustls)
    /// Returns None if the storage backend doesn't support sync operations
    fn read_key_sync(&self) -> Option<Result<Vec<u8>>> {
        None
    }
}

/// Factory for creating storage backends
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend based on the storage type
    pub fn create(storage_type: StorageType, config: &crate::config::Config) -> Result<Box<dyn Storage>> {
        match storage_type {
            StorageType::File => {
                Ok(Box::new(FileStorage::new(config)?))
            }
            StorageType::Redis => {
                Ok(Box::new(RedisStorage::new(config)?))
            }
        }
    }

    /// Create storage from AppConfig storage settings
    pub fn create_from_app_config(app_config: &crate::config::AppConfig, domain_config: &crate::config::Config) -> Result<Box<dyn Storage>> {
        let storage_type = match app_config.storage.storage_type.as_str() {
            "redis" => StorageType::Redis,
            _ => StorageType::File,
        };
        Self::create(storage_type, domain_config)
    }

    /// Create storage based on config settings
    pub fn create_default(config: &crate::config::Config) -> Result<Box<dyn Storage>> {
        // Check if storage type is specified in config
        let storage_type = if let Some(storage_type_str) = &config.opts.storage_type {
            match storage_type_str.as_str() {
                "redis" => StorageType::Redis,
                _ => StorageType::File,
            }
        } else {
            StorageType::File
        };
        Self::create(storage_type, config)
    }
}

