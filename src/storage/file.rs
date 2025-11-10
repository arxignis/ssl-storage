//! File system storage backend implementation (certbot-style)

use crate::config::Config;
use crate::storage::Storage;
use anyhow::{Context, Result};
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
        let mut well_known_folder = self.static_path.clone();
        well_known_folder.push("well-known");
        tokio::fs::create_dir_all(&well_known_folder)
            .await
            .with_context(|| format!("Failed to create well-known directory {:?}", well_known_folder))?;

        let mut challenge_path = well_known_folder.clone();
        challenge_path.push("acme-challenge");
        tokio::fs::create_dir_all(&challenge_path)
            .await
            .with_context(|| format!("Failed to create acme-challenge directory {:?}", challenge_path))?;

        challenge_path.push(token);
        tokio::fs::write(&challenge_path, key_auth)
            .await
            .with_context(|| format!("Failed to write challenge file {:?}", challenge_path))?;
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
}
