//! File system storage backend implementation (certbot-style)

use crate::config::Config;
use crate::storage::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::path::PathBuf;

/// File system storage backend (certbot-style structure)
pub struct FileStorage {
    base_path: PathBuf,
    domain: String,
    static_path: PathBuf,
}

impl FileStorage {
    /// Create a new file storage backend
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            base_path: config.https_path.clone(),
            domain: config.opts.domain.clone(),
            static_path: config.static_path.clone(),
        })
    }

    /// Get the archive directory path
    fn archive_dir(&self) -> PathBuf {
        let mut path = self.base_path.clone();
        path.push("archive");
        path.push(&self.domain);
        path
    }

    /// Get the live directory path
    fn live_dir(&self) -> PathBuf {
        let mut path = self.base_path.clone();
        path.push("live");
        path.push(&self.domain);
        path
    }


    /// Get the next version number for archive files
    async fn get_next_version(&self) -> Result<u32> {
        let archive_dir = self.archive_dir();
        if !archive_dir.exists() {
            return Ok(1);
        }

        let mut max_version = 0u32;
        let mut entries = tokio::fs::read_dir(&archive_dir).await
            .with_context(|| format!("Failed to read archive directory {:?}", archive_dir))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Look for cert1.pem, cert2.pem, etc.
            if name.starts_with("cert") && name.ends_with(".pem") {
                if let Some(version_str) = name.strip_prefix("cert").and_then(|s| s.strip_suffix(".pem")) {
                    if let Ok(version) = version_str.parse::<u32>() {
                        max_version = max_version.max(version);
                    }
                }
            }
        }

        Ok(max_version + 1)
    }

    /// Create symlinks in live/ directory pointing to archive/
    async fn create_symlinks(&self, version: u32) -> Result<()> {
        let live_dir = self.live_dir();
        tokio::fs::create_dir_all(&live_dir)
            .await
            .with_context(|| format!("Failed to create live directory {:?}", live_dir))?;

        // Create symlinks
        let symlinks = [
            ("cert.pem", format!("cert{}.pem", version)),
            ("chain.pem", format!("chain{}.pem", version)),
            ("fullchain.pem", format!("fullchain{}.pem", version)),
            ("privkey.pem", format!("privkey{}.pem", version)),
        ];

        for (link_name, target_name) in symlinks.iter() {
            let link_path = live_dir.join(link_name);

            // Remove existing symlink or file
            if link_path.exists() {
                tokio::fs::remove_file(&link_path).await.ok();
            }

            // Create symlink (use relative path from live to archive)
            let relative_target = format!("../../archive/{}/{}", &self.domain, target_name);

            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                symlink(&relative_target, &link_path)
                    .with_context(|| format!("Failed to create symlink {:?} -> {:?}", link_path, relative_target))?;
            }
            #[cfg(not(unix))]
            {
                // On non-Unix systems, copy the file instead
                let archive_dir = self.archive_dir();
                let target_path = archive_dir.join(target_name);
                tokio::fs::copy(&target_path, &link_path).await
                    .with_context(|| format!("Failed to copy {:?} to {:?}", target_path, link_path))?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Storage for FileStorage {
    async fn read_cert(&self) -> Result<Vec<u8>> {
        let path = self.live_dir().join("cert.pem");
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read certificate from {:?}", path))
    }

    async fn read_chain(&self) -> Result<Vec<u8>> {
        let path = self.live_dir().join("chain.pem");
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read chain from {:?}", path))
    }

    async fn read_fullchain(&self) -> Result<Vec<u8>> {
        let path = self.live_dir().join("fullchain.pem");
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read fullchain from {:?}", path))
    }

    async fn read_key(&self) -> Result<Vec<u8>> {
        let path = self.live_dir().join("privkey.pem");
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read private key from {:?}", path))
    }

    async fn write_certs(&self, cert: &[u8], chain: &[u8], key: &[u8]) -> Result<()> {
        let version = self.get_next_version().await?;
        let archive_dir = self.archive_dir();

        // Create archive directory
        tokio::fs::create_dir_all(&archive_dir)
            .await
            .with_context(|| format!("Failed to create archive directory {:?}", archive_dir))?;

        // Combine cert and chain to create fullchain
        let mut fullchain = cert.to_vec();
        fullchain.extend_from_slice(chain);

        // Calculate SHA256 hash of fullchain + key for change detection
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&fullchain);
        hasher.update(key);
        let hash = format!("{:x}", hasher.finalize());

        // Write versioned files to archive
        let files = [
            (format!("cert{}.pem", version), cert),
            (format!("chain{}.pem", version), chain),
            (format!("fullchain{}.pem", version), &fullchain),
            (format!("privkey{}.pem", version), key),
        ];

        for (filename, content) in files.iter() {
            let file_path = archive_dir.join(filename);
            tokio::fs::write(&file_path, content)
                .await
                .with_context(|| format!("Failed to write {:?} to {:?}", filename, file_path))?;
        }

        // Create symlinks in live directory
        self.create_symlinks(version).await?;

        // Store certificate hash for change detection
        let hash_path = self.live_dir().join("certificate_hash");
        tokio::fs::write(&hash_path, &hash)
            .await
            .with_context(|| format!("Failed to write certificate hash to {:?}", hash_path))?;

        Ok(())
    }

    async fn cert_exists(&self) -> bool {
        self.live_dir().join("cert.pem").exists()
    }

    async fn read_created_at(&self) -> Result<chrono::DateTime<chrono::Utc>> {
        let path = self.live_dir().join("certs_created_at");
        let content = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("Unable to read {:?}", &path))?;
        content
            .parse::<chrono::DateTime<chrono::Utc>>()
            .with_context(|| format!("Failed to parse {:?}", &path))
    }

    async fn write_created_at(&self, created_at: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let path = self.live_dir().join("certs_created_at");
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .with_context(|| format!("Failed to create parent directory for {:?}", path))?;
        tokio::fs::write(&path, created_at.to_string())
            .await
            .with_context(|| format!("Unable to write {:?}", &path))?;
        Ok(())
    }

    async fn write_challenge(&self, token: &str, key_auth: &str) -> Result<()> {
        // Write challenge files to a shared location (not per-domain)
        // This allows the HTTP server to serve them from a single base path
        // The static_path is per-domain, but we need to write to the parent directory
        let base_path = self.static_path.parent()
            .ok_or_else(|| anyhow!("Cannot get parent path from static_path"))?
            .to_path_buf();

        let mut well_known_folder = base_path.clone();
        well_known_folder.push("well-known");
        tokio::fs::create_dir_all(&well_known_folder)
            .await
            .with_context(|| format!("Failed to create well-known directory {:?}", well_known_folder))?;

        let mut challenge_path = well_known_folder.clone();
        challenge_path.push("acme-challenge");
        tokio::fs::create_dir_all(&challenge_path)
            .await
            .with_context(|| format!("Failed to create acme-challenge directory {:?}", challenge_path))?;

        // Write challenge file
        let mut challenge_file = challenge_path.clone();
        challenge_file.push(token);
        tokio::fs::write(&challenge_file, key_auth)
            .await
            .with_context(|| format!("Failed to write challenge file {:?}", challenge_file))?;

        // Write challenge timestamp
        let timestamp = chrono::Utc::now();
        let mut timestamp_file = challenge_path.clone();
        timestamp_file.push(format!("{}.timestamp", token));
        tokio::fs::write(&timestamp_file, timestamp.to_rfc3339())
            .await
            .with_context(|| format!("Failed to write challenge timestamp {:?}", timestamp_file))?;

        Ok(())
    }

    fn static_path(&self) -> PathBuf {
        self.static_path.clone()
    }

    fn read_fullchain_sync(&self) -> Option<Result<Vec<u8>>> {
        let path = self.live_dir().join("fullchain.pem");
        Some(std::fs::read(&path)
            .with_context(|| format!("Failed to read fullchain from {:?}", path)))
    }

    fn read_key_sync(&self) -> Option<Result<Vec<u8>>> {
        let path = self.live_dir().join("privkey.pem");
        Some(std::fs::read(&path)
            .with_context(|| format!("Failed to read private key from {:?}", path)))
    }

    async fn write_dns_challenge(&self, domain: &str, dns_record: &str, dns_value: &str) -> Result<()> {
        // For file storage, save DNS challenge info to a file
        let mut dns_challenge_dir = self.base_path.clone();
        dns_challenge_dir.push(domain);
        dns_challenge_dir.push("dns-challenges");

        tokio::fs::create_dir_all(&dns_challenge_dir)
            .await
            .with_context(|| format!("Failed to create dns-challenges directory {:?}", dns_challenge_dir))?;

        let mut challenge_file = dns_challenge_dir.clone();
        challenge_file.push(format!("{}.txt", dns_record.replace(".", "_")));

        let challenge_data = format!("{} IN TXT {}\n", dns_record, dns_value);
        tokio::fs::write(&challenge_file, challenge_data)
            .await
            .with_context(|| format!("Failed to write DNS challenge file {:?}", challenge_file))?;

        // Write DNS challenge timestamp
        let timestamp = chrono::Utc::now();
        let mut timestamp_file = dns_challenge_dir.clone();
        timestamp_file.push(format!("{}.timestamp", domain));
        tokio::fs::write(&timestamp_file, timestamp.to_rfc3339())
            .await
            .with_context(|| format!("Failed to write DNS challenge timestamp {:?}", timestamp_file))?;

        Ok(())
    }

    async fn read_account_credentials(&self) -> Result<Option<String>> {
        let mut creds_path = self.base_path.clone();
        creds_path.push("acme_account_credentials.json");

        if !creds_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&creds_path)
            .await
            .with_context(|| format!("Failed to read account credentials from {:?}", creds_path))?;

        Ok(Some(content))
    }

    async fn write_account_credentials(&self, credentials: &str) -> Result<()> {
        let mut creds_path = self.base_path.clone();
        creds_path.push("acme_account_credentials.json");

        tokio::fs::create_dir_all(creds_path.parent().unwrap())
            .await
            .with_context(|| format!("Failed to create parent directory for {:?}", creds_path))?;

        tokio::fs::write(&creds_path, credentials)
            .await
            .with_context(|| format!("Failed to write account credentials to {:?}", creds_path))?;

        Ok(())
    }

    async fn record_failure(&self, error: &str) -> Result<()> {
        let failure_path = self.live_dir().join("cert_failure.json");
        let count_path = self.live_dir().join("cert_failure_count");

        // Read current failure count
        let mut count = 0u32;
        if count_path.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&count_path).await {
                count = content.trim().parse().unwrap_or(0);
            }
        }

        // Increment failure count
        count += 1;

        // Write failure record
        let failure_data = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "error": error,
            "count": count,
        });

        tokio::fs::create_dir_all(failure_path.parent().unwrap())
            .await
            .with_context(|| format!("Failed to create parent directory for {:?}", failure_path))?;

        tokio::fs::write(&failure_path, serde_json::to_string_pretty(&failure_data)?)
            .await
            .with_context(|| format!("Failed to write failure record to {:?}", failure_path))?;

        // Write failure count
        tokio::fs::write(&count_path, count.to_string())
            .await
            .with_context(|| format!("Failed to write failure count to {:?}", count_path))?;

        Ok(())
    }

    async fn get_last_failure(&self) -> Result<Option<(chrono::DateTime<chrono::Utc>, String)>> {
        let failure_path = self.live_dir().join("cert_failure.json");

        if !failure_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&failure_path)
            .await
            .with_context(|| format!("Failed to read failure record from {:?}", failure_path))?;

        let failure_data: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse failure record from {:?}", failure_path))?;

        let timestamp_str = failure_data["timestamp"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing timestamp in failure record"))?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .with_context(|| format!("Failed to parse timestamp: {}", timestamp_str))?
            .with_timezone(&chrono::Utc);

        let error = failure_data["error"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing error in failure record"))?
            .to_string();

        Ok(Some((timestamp, error)))
    }

    async fn clear_failure(&self) -> Result<()> {
        let failure_path = self.live_dir().join("cert_failure.json");
        let count_path = self.live_dir().join("cert_failure_count");

        if failure_path.exists() {
            tokio::fs::remove_file(&failure_path).await.ok();
        }

        if count_path.exists() {
            tokio::fs::remove_file(&count_path).await.ok();
        }

        Ok(())
    }

    async fn get_failure_count(&self) -> Result<u32> {
        let count_path = self.live_dir().join("cert_failure_count");

        if !count_path.exists() {
            return Ok(0);
        }

        let content = tokio::fs::read_to_string(&count_path)
            .await
            .with_context(|| format!("Failed to read failure count from {:?}", count_path))?;

        let count = content.trim().parse::<u32>()
            .with_context(|| format!("Failed to parse failure count: {}", content))?;

        Ok(count)
    }

    async fn get_certificate_hash(&self) -> Result<Option<String>> {
        let hash_path = self.live_dir().join("certificate_hash");

        // If hash exists, return it
        if hash_path.exists() {
            let content = tokio::fs::read_to_string(&hash_path)
                .await
                .with_context(|| format!("Failed to read certificate hash from {:?}", hash_path))?;
            return Ok(Some(content.trim().to_string()));
        }

        // Hash doesn't exist, but check if certificate exists
        if !self.cert_exists().await {
            return Ok(None);
        }

        // Certificate exists but hash doesn't - generate it
        let fullchain = self.read_fullchain().await?;
        let key = self.read_key().await?;

        // Calculate SHA256 hash of fullchain + key
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&fullchain);
        hasher.update(&key);
        let hash = format!("{:x}", hasher.finalize());

        // Store the hash for future use
        tokio::fs::write(&hash_path, &hash)
            .await
            .with_context(|| format!("Failed to write certificate hash to {:?}", hash_path))?;

        Ok(Some(hash))
    }

    async fn get_challenge_timestamp(&self, token: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let base_path = self.static_path.parent()
            .ok_or_else(|| anyhow!("Cannot get parent path from static_path"))?
            .to_path_buf();

        let mut timestamp_path = base_path.clone();
        timestamp_path.push("well-known");
        timestamp_path.push("acme-challenge");
        timestamp_path.push(format!("{}.timestamp", token));

        if !timestamp_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&timestamp_path)
            .await
            .with_context(|| format!("Failed to read challenge timestamp from {:?}", timestamp_path))?;

        let timestamp = chrono::DateTime::parse_from_rfc3339(content.trim())
            .with_context(|| format!("Failed to parse challenge timestamp: {}", content))?
            .with_timezone(&chrono::Utc);

        Ok(Some(timestamp))
    }

    async fn get_dns_challenge_timestamp(&self, domain: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let mut timestamp_path = self.base_path.clone();
        timestamp_path.push(domain);
        timestamp_path.push("dns-challenges");
        timestamp_path.push(format!("{}.timestamp", domain));

        if !timestamp_path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&timestamp_path)
            .await
            .with_context(|| format!("Failed to read DNS challenge timestamp from {:?}", timestamp_path))?;

        let timestamp = chrono::DateTime::parse_from_rfc3339(content.trim())
            .with_context(|| format!("Failed to parse DNS challenge timestamp: {}", content))?
            .with_timezone(&chrono::Utc);

        Ok(Some(timestamp))
    }

    async fn is_challenge_expired(&self, token: &str, max_ttl_seconds: u64) -> Result<bool> {
        let timestamp = match self.get_challenge_timestamp(token).await? {
            Some(ts) => ts,
            None => return Ok(true), // No timestamp means expired
        };

        let now = chrono::Utc::now();
        let age = now - timestamp;
        let age_seconds = age.num_seconds() as u64;

        Ok(age_seconds >= max_ttl_seconds)
    }

    async fn is_dns_challenge_expired(&self, domain: &str, max_ttl_seconds: u64) -> Result<bool> {
        let timestamp = match self.get_dns_challenge_timestamp(domain).await? {
            Some(ts) => ts,
            None => return Ok(true), // No timestamp means expired
        };

        let now = chrono::Utc::now();
        let age = now - timestamp;
        let age_seconds = age.num_seconds() as u64;

        Ok(age_seconds >= max_ttl_seconds)
    }

    async fn cleanup_expired_challenges(&self, max_ttl_seconds: u64) -> Result<()> {
        let base_path = self.static_path.parent()
            .ok_or_else(|| anyhow!("Cannot get parent path from static_path"))?
            .to_path_buf();

        let mut challenge_dir = base_path.clone();
        challenge_dir.push("well-known");
        challenge_dir.push("acme-challenge");

        if !challenge_dir.exists() {
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(&challenge_dir).await
            .with_context(|| format!("Failed to read challenge directory {:?}", challenge_dir))?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Skip timestamp files
            if name.ends_with(".timestamp") {
                continue;
            }

            // Check if challenge is expired
            if let Ok(expired) = self.is_challenge_expired(&name, max_ttl_seconds).await {
                if expired {
                    let file_path = entry.path();
                    let timestamp_path = challenge_dir.join(format!("{}.timestamp", name));

                    // Remove challenge file and timestamp
                    tokio::fs::remove_file(&file_path).await.ok();
                    tokio::fs::remove_file(&timestamp_path).await.ok();
                }
            }
        }

        Ok(())
    }
}
