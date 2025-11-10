//! Everything required for setting up HTTPS / TLS.
//! Instantiate a server for HTTP-01 check with letsencrypt,
//! checks if certificates are not outdated,
//! persists files on disk.

mod errors;
mod config;
mod storage;
mod domain_reader;

pub use errors::AtomicServerResult;
pub use config::{Config, ConfigOpts, AppConfig, RetryConfig};
pub use storage::{Storage, StorageFactory, StorageType};
pub use domain_reader::{DomainConfig, DomainReader, DomainReaderFactory};

use actix_web::{App, HttpServer, HttpResponse, web, Responder};
use anyhow::{anyhow, Context};
use serde::Serialize;
use std::io::BufReader;
use tracing::{info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Create RUSTLS server config from certificates in storage
pub fn get_https_config(
    config: &crate::config::Config,
) -> AtomicServerResult<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // Create storage backend (file system by default)
    let storage = StorageFactory::create_default(config)?;

    // Read fullchain synchronously (rustls requires sync)
    // Use fullchain which includes both cert and chain
    let fullchain_bytes = storage.read_fullchain_sync()
        .ok_or_else(|| anyhow!("Storage backend does not support synchronous fullchain reading"))??;

    let key_bytes = storage.read_key_sync()
        .ok_or_else(|| anyhow!("Storage backend does not support synchronous key reading"))??;

    let cert_file = &mut BufReader::new(std::io::Cursor::new(fullchain_bytes));
    let key_file = &mut BufReader::new(std::io::Cursor::new(key_bytes));

    let mut cert_chain = Vec::new();
    for cert_result in certs(cert_file) {
        let cert = cert_result.context("Failed to parse certificate")?;
        cert_chain.push(CertificateDer::from(cert));
    }

    let mut keys: Vec<PrivateKeyDer> = pkcs8_private_keys(key_file)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse private key")?
        .into_iter()
        .map(PrivateKeyDer::Pkcs8)
        .collect();

    if keys.is_empty() {
        return Err(anyhow!("No key found. Consider deleting the storage directory and restart to create new keys."));
    }

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .context("Unable to create HTTPS config from certificates")?;

    Ok(server_config)
}

/// Check if a failed certificate should be retried based on exponential backoff
pub async fn should_retry_failed_cert(
    config: &crate::config::Config,
    retry_config: &crate::config::RetryConfig,
) -> AtomicServerResult<bool> {
    let storage = StorageFactory::create_default(config)?;

    // Check if there's a failure record
    let last_failure = match storage.get_last_failure().await {
        Ok(Some((timestamp, _))) => timestamp,
        Ok(None) => return Ok(false), // No failure recorded
        Err(e) => {
            warn!("Failed to read failure record: {}", e);
            return Ok(false);
        }
    };

    // Check if max retries exceeded
    let failure_count = storage.get_failure_count().await.unwrap_or(0);
    if retry_config.max_retries > 0 && failure_count >= retry_config.max_retries {
        warn!("Maximum retry count ({}) exceeded for domain {}. Skipping retry.", retry_config.max_retries, config.opts.domain);
        return Ok(false);
    }

    // Calculate exponential backoff delay
    // Formula: min(min_retry_delay * 2^(failure_count - 1), max_retry_delay)
    let base_delay = retry_config.min_retry_delay_seconds as f64;
    let exponential_delay = base_delay * (2.0_f64.powi((failure_count.saturating_sub(1)) as i32));
    let delay_seconds = exponential_delay.min(retry_config.max_retry_delay_seconds as f64) as u64;

    let now = chrono::Utc::now();
    let time_since_failure = now - last_failure;
    let time_since_failure_secs = time_since_failure.num_seconds() as u64;

    if time_since_failure_secs >= delay_seconds {
        info!("Retry delay ({}) has passed for domain {}. Last failure was {} seconds ago. Will retry.", delay_seconds, config.opts.domain, time_since_failure_secs);
        Ok(true)
    } else {
        let remaining = delay_seconds - time_since_failure_secs;
        info!("Retry delay not yet reached for domain {}. Will retry in {} seconds.", config.opts.domain, remaining);
        Ok(false)
    }
}

/// Checks if the certificates need to be renewed.
/// Will be true if there are no certs yet.
pub async fn should_renew_certs_check(config: &crate::config::Config) -> AtomicServerResult<bool> {
    let storage = StorageFactory::create_default(config)?;

    if !storage.cert_exists().await {
        info!(
            "No HTTPS certificates found, requesting new ones...",
        );
        return Ok(true);
    }

    // Ensure certificate hash exists (generate if missing for backward compatibility)
    if let Err(e) = storage.get_certificate_hash().await {
        warn!("Failed to get or generate certificate hash: {}", e);
    }

    let created_at = match storage.read_created_at().await {
        Ok(dt) => dt,
        Err(_) => {
            // If we can't read the created_at file, assume certificates need renewal
            warn!("Unable to read certificate creation timestamp, assuming renewal needed");
            return Ok(true);
        }
    };

    let certs_age: chrono::Duration = chrono::Utc::now() - created_at;
    // Let's Encrypt certificates are valid for three months, but I think renewing earlier provides a better UX
    let expired = certs_age > chrono::Duration::weeks(4);
    if expired {
        warn!("HTTPS Certificates expired, requesting new ones...")
    };
    Ok(expired)
}

#[derive(Debug, Serialize)]
struct CertificateExpirationInfo {
    domain: String,
    exists: bool,
    created_at: Option<String>,
    expires_at: Option<String>,
    age_days: Option<i64>,
    expires_in_days: Option<i64>,
    needs_renewal: bool,
    #[serde(default)]
    renewing: bool,
}

/// Get certificate expiration information for a domain
async fn get_cert_expiration_info(
    app_config: &crate::config::AppConfig,
    domain: &str,
    base_https_path: &std::path::PathBuf,
) -> anyhow::Result<CertificateExpirationInfo> {
    let domain_cfg = {
        let domain_config = crate::domain_reader::DomainConfig {
            domain: domain.to_string(),
            email: None,
            dns: false,
            wildcard: false,
        };
        app_config.create_domain_config(&domain_config, base_https_path.clone())
    };

    let storage = StorageFactory::create_default(&domain_cfg)?;
    let exists = storage.cert_exists().await;

    if !exists {
        return Ok(CertificateExpirationInfo {
            domain: domain.to_string(),
            exists: false,
            created_at: None,
            expires_at: None,
            age_days: None,
            expires_in_days: None,
            needs_renewal: true,
            renewing: false,
        });
    }

    // Ensure certificate hash exists (generate if missing for backward compatibility)
    if let Err(e) = storage.get_certificate_hash().await {
        warn!("Failed to get or generate certificate hash for {}: {}", domain, e);
    }

    let created_at = match storage.read_created_at().await {
        Ok(dt) => dt,
        Err(_) => {
            return Ok(CertificateExpirationInfo {
                domain: domain.to_string(),
                exists: true,
                created_at: None,
                expires_at: None,
                age_days: None,
                expires_in_days: None,
                needs_renewal: true,
                renewing: false,
            });
        }
    };

    // Let's Encrypt certificates are valid for 90 days (3 months)
    let expires_at = created_at + chrono::Duration::days(90);
    let now = chrono::Utc::now();
    let age = now - created_at;
    let expires_in = expires_at - now;

    let needs_renewal = age > chrono::Duration::weeks(4);

    Ok(CertificateExpirationInfo {
        domain: domain.to_string(),
        exists: true,
        created_at: Some(created_at.to_rfc3339()),
        expires_at: Some(expires_at.to_rfc3339()),
        age_days: Some(age.num_days()),
        expires_in_days: Some(expires_in.num_days()),
        needs_renewal,
        renewing: false,
    })
}

/// HTTP handler for certificate expiration check (single domain)
async fn check_cert_expiration_handler(
    app_config: web::Data<crate::config::AppConfig>,
    base_path: web::Data<std::path::PathBuf>,
    path: web::Path<String>,
) -> impl Responder {
    let domain = path.into_inner();
    match get_cert_expiration_info(&app_config, &domain, &base_path).await {
        Ok(mut info) => {
            // If certificate needs renewal, start renewal process in background
            if info.needs_renewal {
                // Read domains to find the domain config
                let domain_reader = match crate::domain_reader::DomainReaderFactory::create(&app_config.domains) {
                    Ok(reader) => reader,
                    Err(e) => {
                        warn!("Error creating domain reader: {}", e);
                        return HttpResponse::Ok().json(info);
                    }
                };

                if let Ok(domains) = domain_reader.read_domains().await {
                    if let Some(domain_config) = domains.iter().find(|d| d.domain == domain) {
                        let app_config_clone = app_config.clone();
                        let base_path_clone = base_path.clone();
                        let domain_config_clone = domain_config.clone();

                        // Spawn renewal task in background
                        tokio::spawn(async move {
                            if let Err(e) = renew_cert_if_needed(&app_config_clone, &domain_config_clone, &base_path_clone).await {
                                warn!("Error renewing certificate for {}: {}", domain_config_clone.domain, e);
                            }
                        });

                        info.renewing = true; // Mark as renewing
                    }
                }
            }
            HttpResponse::Ok().json(info)
        }
        Err(e) => {
            warn!("Error checking certificate expiration for {}: {}", domain, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to check certificate expiration: {}", e)
            }))
        }
    }
}

/// Renew certificate for a domain if needed
async fn renew_cert_if_needed(
    app_config: &crate::config::AppConfig,
    domain_config: &crate::domain_reader::DomainConfig,
    base_path: &std::path::PathBuf,
) -> anyhow::Result<()> {
    let domain_cfg = app_config.create_domain_config(domain_config, base_path.clone());

    if should_renew_certs_check(&domain_cfg).await? {
        info!("Certificate for {} is expiring, starting renewal process...", domain_config.domain);
        request_cert(&domain_cfg).await?;
        info!("Certificate renewed successfully for {}!", domain_config.domain);
    }

    Ok(())
}

/// HTTP handler for checking expiration of all domains
async fn check_all_certs_expiration_handler(
    app_config: web::Data<crate::config::AppConfig>,
    base_path: web::Data<std::path::PathBuf>,
) -> impl Responder {
    // Read domains from the configured source
    let domain_reader = match crate::domain_reader::DomainReaderFactory::create(&app_config.domains) {
        Ok(reader) => reader,
        Err(e) => {
            warn!("Error creating domain reader: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create domain reader: {}", e)
            }));
        }
    };

    let domains = match domain_reader.read_domains().await {
        Ok(domains) => domains,
        Err(e) => {
            warn!("Error reading domains: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read domains: {}", e)
            }));
        }
    };

    // Check expiration for each domain and renew if needed
    let mut results = Vec::new();
    for domain_config in domains.iter() {
        match get_cert_expiration_info(&app_config, &domain_config.domain, &base_path).await {
            Ok(mut info) => {
                // If certificate needs renewal, start renewal process in background
                if info.needs_renewal {
                    let app_config_clone = app_config.clone();
                    let base_path_clone = base_path.clone();
                    let domain_config_clone = domain_config.clone();

                    // Spawn renewal task in background
                    tokio::spawn(async move {
                        if let Err(e) = renew_cert_if_needed(&app_config_clone, &domain_config_clone, &base_path_clone).await {
                            warn!("Error renewing certificate for {}: {}", domain_config_clone.domain, e);
                        }
                    });

                    info.renewing = true; // Mark as renewing
                }
                results.push(info);
            }
            Err(e) => {
                warn!("Error checking certificate expiration for {}: {}", domain_config.domain, e);
                // Add error info for this domain
                results.push(CertificateExpirationInfo {
                    domain: domain_config.domain.clone(),
                    exists: false,
                    created_at: None,
                    expires_at: None,
                    age_days: None,
                    expires_in_days: None,
                    needs_renewal: true,
                    renewing: false,
                });
            }
        }
    }

    HttpResponse::Ok().json(results)
}

/// Check DNS TXT record for DNS-01 challenge
async fn check_dns_txt_record(record_name: &str, expected_value: &str, max_attempts: u32, delay_seconds: u64) -> bool {
    use trust_dns_resolver::TokioAsyncResolver;

    // Use Google DNS as primary resolver (more reliable than system DNS)
    // This ensures we're querying authoritative DNS servers
    let resolver_config = ResolverConfig::google();

    info!("Checking DNS TXT record: {} (expected value: {})", record_name, expected_value);
    info!("DNS lookup settings: max_attempts={}, delay_seconds={}", max_attempts, delay_seconds);

    for attempt in 1..=max_attempts {
        // Create a new resolver for each attempt to ensure no caching
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.use_hosts_file = true;
        resolver_opts.validate = false; // Don't validate DNSSEC to avoid issues
        resolver_opts.attempts = 3; // Retry attempts per query
        resolver_opts.timeout = std::time::Duration::from_secs(5); // 5 second timeout
        resolver_opts.cache_size = 0; // Disable DNS cache by setting cache size to 0

        // Create a fresh DNS resolver for each attempt to avoid any caching
        let resolver = TokioAsyncResolver::tokio(
            resolver_config.clone(),
            resolver_opts,
        );

        match resolver.txt_lookup(record_name).await {
            Ok(lookup) => {
                let mut found_any = false;
                let mut found_values = Vec::new();

                // Check if any TXT record matches the expected value
                for record in lookup.iter() {
                    for txt_data in record.iter() {
                        let txt_string = String::from_utf8_lossy(txt_data).trim().to_string();
                        found_any = true;
                        found_values.push(txt_string.clone());

                        if txt_string == expected_value {
                            info!("DNS TXT record matches expected value on attempt {}: {}", attempt, txt_string);
                            return true;
                        }
                    }
                }

                if found_any {
                    if attempt == 1 || attempt % 6 == 0 {
                        warn!("DNS record found but value doesn't match. Expected: '{}', Found: {:?}", expected_value, found_values);
                    }
                } else {
                    if attempt % 6 == 0 {
                        info!("DNS record not found yet (attempt {}/{})...", attempt, max_attempts);
                    }
                }
            }
            Err(e) => {
                if attempt == 1 || attempt % 6 == 0 {
                    warn!("DNS lookup error on attempt {}: {}", attempt, e);
                }
            }
        }

        if attempt < max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(delay_seconds)).await;
        }
    }

    warn!("DNS TXT record not found after {} attempts", max_attempts);
    false
}

/// Writes challenge file for HTTP-01 challenge
/// The main HTTP server will serve this file - no temporary server needed
async fn cert_init_server(
    config: &crate::config::Config,
    challenge: &instant_acme::Challenge,
    key_auth: &str,
) -> AtomicServerResult<()> {
    let storage = StorageFactory::create_default(config)?;
    storage.write_challenge(&challenge.token.to_string(), key_auth).await?;

    info!("Challenge file written. Main HTTP server will serve it at /.well-known/acme-challenge/{}", challenge.token);

    Ok(())
}

/// Sends a request to LetsEncrypt to create a certificate
pub async fn request_cert(config: &crate::config::Config) -> AtomicServerResult<()> {
    // Check if using Redis storage - if so, use distributed lock to prevent race conditions
    let storage_type = if let Some(storage_type_str) = &config.opts.storage_type {
        match storage_type_str.as_str() {
            "redis" => crate::storage::StorageType::Redis,
            _ => crate::storage::StorageType::File,
        }
    } else {
        crate::storage::StorageType::File
    };

    if storage_type == crate::storage::StorageType::Redis {
        // Use distributed lock for Redis storage to prevent multiple instances from processing the same domain
        // Create RedisStorage directly to access lock methods
        let redis_storage = crate::storage::RedisStorage::new(config)?;

        // Lock TTL from config (default: 900 seconds = 15 minutes)
        let lock_ttl_seconds = config.opts.lock_ttl_seconds.unwrap_or(900);

        return redis_storage.with_lock(lock_ttl_seconds, || async {
            request_cert_internal(config).await
        }).await;
    }

    // For file storage, proceed without lock
    request_cert_internal(config).await
}

/// Parse retry-after timestamp from rate limit error message
/// Returns the retry-after timestamp if found, None otherwise
fn parse_retry_after(error_msg: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    // Look for "retry after YYYY-MM-DD HH:MM:SS UTC" pattern
    if let Some(pos) = error_msg.find("retry after") {
        let after_text = &error_msg[pos + "retry after".len()..].trim();
        // Try to parse the timestamp (format: "2025-11-10 18:08:38 UTC")
        if let Ok(dt) = chrono::DateTime::parse_from_str(after_text, "%Y-%m-%d %H:%M:%S %Z") {
            return Some(dt.with_timezone(&chrono::Utc));
        }
        // Try alternative format without timezone (assume UTC)
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(after_text, "%Y-%m-%d %H:%M:%S") {
            return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
        }
        // Try parsing as RFC3339 format
        if let Ok(dt) = after_text.parse::<chrono::DateTime<chrono::Utc>>() {
            return Some(dt);
        }
    }
    None
}

/// Helper function to check if an account already exists
async fn check_account_exists(
    email: &str,
    lets_encrypt_url: &str,
) -> Result<Option<(instant_acme::Account, instant_acme::AccountCredentials)>, anyhow::Error> {
    match instant_acme::Account::builder()
        .context("Failed to create account builder")?
        .create(
            &instant_acme::NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: true,
            },
            lets_encrypt_url.to_string(),
            None,
        )
        .await
    {
        Ok((acc, cr)) => Ok(Some((acc, cr))),
        Err(e) => {
            let error_msg = format!("{}", e);
            // If it's a rate limit error, propagate it
            if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                return Err(e.into());
            }
            // Otherwise, account doesn't exist
            Ok(None)
        }
    }
}

/// Helper function to create a new Let's Encrypt account and save credentials
/// Handles rate limits by waiting for the retry-after time
async fn create_new_account(
    storage: &Box<dyn Storage>,
    email: &str,
    lets_encrypt_url: &str,
) -> AtomicServerResult<(instant_acme::Account, instant_acme::AccountCredentials)> {
    // First, check if account already exists
    match check_account_exists(email, lets_encrypt_url).await {
        Ok(Some((acc, cr))) => {
            info!("Account already exists for email {}, reusing it", email);
            return Ok((acc, cr));
        }
        Ok(None) => {
            // Account doesn't exist, proceed to create
        }
        Err(e) => {
            // Check if it's a rate limit error
            let error_msg = format!("{}", e);
            if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                if let Some(retry_after) = parse_retry_after(&error_msg) {
                    let now = chrono::Utc::now();
                    if retry_after > now {
                        let wait_duration = retry_after - now;
                        let wait_secs = wait_duration.num_seconds().max(0) as u64;
                        warn!("Rate limit hit. Waiting {} seconds until {} before retrying account creation", wait_secs, retry_after);
                        tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs + 1)).await;
                    }
                } else {
                    // Rate limit error but couldn't parse retry-after, wait a default time
                    warn!("Rate limit hit but couldn't parse retry-after time. Waiting 3 hours (10800 seconds) before retrying");
                    tokio::time::sleep(tokio::time::Duration::from_secs(10800)).await;
                }
            } else {
                // Not a rate limit error, propagate it
                return Err(e);
            }
        }
    }

    info!("Creating new LetsEncrypt account with email {}", email);

    // Retry account creation (after waiting for rate limit if needed)
    let max_retries = 3;
    let mut retry_count = 0;

    loop {
        match instant_acme::Account::builder()
            .context("Failed to create account builder")?
            .create(
                &instant_acme::NewAccount {
                    contact: &[&format!("mailto:{}", email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                lets_encrypt_url.to_string(),
                None,
            )
            .await
        {
            Ok((account, creds)) => {
                // Save credentials for future use (store as JSON value for now)
                if let Ok(creds_json) = serde_json::to_string(&creds) {
                    if let Err(e) = storage.write_account_credentials(&creds_json).await {
                        warn!("Failed to save account credentials to storage: {}. Account will be recreated on next run.", e);
                    } else {
                        info!("Saved LetsEncrypt account credentials to storage");
                    }
                } else {
                    warn!("Failed to serialize account credentials. Account will be recreated on next run.");
                }
                return Ok((account, creds));
            }
            Err(e) => {
                let error_msg = format!("{}", e);

                // Check if it's a rate limit error
                if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                    if let Some(retry_after) = parse_retry_after(&error_msg) {
                        let now = chrono::Utc::now();
                        if retry_after > now {
                            let wait_duration = retry_after - now;
                            let wait_secs = wait_duration.num_seconds().max(0) as u64;
                            warn!("Rate limit hit during account creation. Waiting {} seconds until {} before retrying", wait_secs, retry_after);
                            tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs + 1)).await;
                            retry_count += 1;
                            if retry_count < max_retries {
                                continue;
                            }
                        }
                    } else {
                        // Rate limit error but couldn't parse retry-after
                        if retry_count < max_retries {
                            let wait_secs = 10800; // 3 hours default
                            warn!("Rate limit hit but couldn't parse retry-after time. Waiting {} seconds before retrying", wait_secs);
                            tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs)).await;
                            retry_count += 1;
                            continue;
                        }
                    }
                }

                // If we've exhausted retries or it's not a rate limit error, return the error
                return Err(e).context("Failed to create account");
            }
        }
    }
}

async fn request_cert_internal(config: &crate::config::Config) -> AtomicServerResult<()> {
    use instant_acme::OrderStatus;

    // Detect wildcard domain and automatically use DNS-01
    let is_wildcard = config.opts.domain.starts_with("*.");
    let use_dns = config.opts.https_dns || is_wildcard;

    if is_wildcard && !config.opts.https_dns {
        warn!("Wildcard domain detected ({}), automatically using DNS-01 challenge", config.opts.domain);
    }

    let challenge_type = if use_dns {
        info!("Using DNS-01 challenge");
        instant_acme::ChallengeType::Dns01
    } else {
        info!("Using HTTP-01 challenge");
        instant_acme::ChallengeType::Http01
    };

    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let lets_encrypt_url = if config.opts.development {
        warn!(
            "Using LetsEncrypt staging server, not production. This is for testing purposes only and will not provide a working certificate."
        );
        instant_acme::LetsEncrypt::Staging.url()
    } else {
        instant_acme::LetsEncrypt::Production.url()
    };

    let email =
        config.opts.email.clone().expect(
            "No email set - required for HTTPS certificate initialization with LetsEncrypt",
        );

    // Try to load existing account credentials from storage
    let storage = StorageFactory::create_default(config)?;
    let existing_creds = storage.read_account_credentials().await
        .context("Failed to read account credentials from storage")?;

    // Try to restore account from stored credentials, but fall back to creating new account if it fails
    let (account, _creds) = match existing_creds {
        Some(creds_json) => {
            // Try to restore account from existing credentials
            info!("Attempting to restore LetsEncrypt account from stored credentials");

            // First try to parse and restore from stored credentials
            match serde_json::from_str::<instant_acme::AccountCredentials>(&creds_json) {
                Ok(creds) => {
                    // Try to restore account from credentials
                    // Use AccountBuilder to restore from credentials
                    match instant_acme::Account::builder()
                        .context("Failed to create account builder")?
                        .from_credentials(creds)
                        .await
                    {
                        Ok(acc) => {
                            info!("Successfully restored LetsEncrypt account from stored credentials");
                            // Get the credentials back from the account (they're stored in the account)
                            // For now, we'll use the stored credentials JSON
                            let restored_creds = serde_json::from_str::<instant_acme::AccountCredentials>(&creds_json)
                                .expect("Credentials were just parsed successfully");
                            (acc, restored_creds)
                        }
                        Err(e) => {
                            let error_msg = format!("{}", e);
                            warn!("Failed to restore account from stored credentials: {}. Will check if account exists.", error_msg);

                            // If restoration fails, check if account exists
                            match check_account_exists(&email, lets_encrypt_url).await {
                                Ok(Some((acc, cr))) => {
                                    info!("Account exists but credentials were invalid. Using existing account.");
                                    (acc, cr)
                                }
                                Ok(None) => {
                                    warn!("Stored credentials invalid and account doesn't exist. Creating new account.");
                                    create_new_account(&storage, &email, lets_encrypt_url).await?
                                }
                                Err(e) => {
                                    let error_msg = format!("{}", e);
                                    if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                                        warn!("Rate limit hit while checking account. Will wait and retry in create_new_account.");
                                        create_new_account(&storage, &email, lets_encrypt_url).await?
                                    } else {
                                        warn!("Failed to check account existence: {}. Creating new account.", e);
                                        create_new_account(&storage, &email, lets_encrypt_url).await?
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse stored credentials: {}. Creating new account.", e);
                    create_new_account(&storage, &email, lets_encrypt_url).await?
                }
            }
        }
        None => {
            // No stored credentials, create a new account
            create_new_account(&storage, &email, lets_encrypt_url).await?
        }
    };

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let mut domain = config.opts.domain.clone();
    // Remove wildcard prefix if present (we'll add it back if needed)
    if domain.starts_with("*.") {
        domain = domain.strip_prefix("*.").unwrap().to_string();
    }

    if use_dns {
        // Set a wildcard subdomain. Not possible with Http-01 challenge, only Dns-01.
        domain = format!("*.{}", domain);
    }
    let identifier = instant_acme::Identifier::Dns(domain);
    let identifiers = vec![identifier];
    let storage = StorageFactory::create_default(config)?;
    let mut order = match account
        .new_order(&instant_acme::NewOrder::new(&identifiers))
        .await
    {
        Ok(order) => order,
        Err(e) => {
            let error_msg = format!("Failed to create new order for domain {}: {}", config.opts.domain, e);
            warn!("{}. Skipping certificate request.", error_msg);
            if let Err(record_err) = storage.record_failure(&error_msg).await {
                warn!("Failed to record failure: {}", record_err);
            }
            return Ok(());
        }
    };

    assert!(matches!(
        order.state().status,
        instant_acme::OrderStatus::Pending
    ));

    // Pick the desired challenge type and prepare the response.
    let mut authorizations = order.authorizations();
    let mut challenges_set = Vec::new();

    while let Some(result) = authorizations.next().await {
        let mut authz = match result {
            Ok(authz) => authz,
            Err(e) => {
                warn!("Failed to get authorization: {}. Skipping this authorization.", e);
                continue;
            }
        };
        let domain = authz.identifier().to_string();

        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let mut challenge = match authz.challenge(challenge_type.clone()) {
            Some(c) => c,
            None => {
                warn!("Domain '{}': No {:?} challenge found, skipping", domain, challenge_type);
                continue;
            }
        };

        let key_auth = challenge.key_authorization().as_str().to_string();
        match challenge_type {
            instant_acme::ChallengeType::Http01 => {
                // Check if existing challenge is expired and clean it up
                let storage = StorageFactory::create_default(config)?;
                let challenge_token = challenge.token.to_string();
                if let Ok(Some(_)) = storage.get_challenge_timestamp(&challenge_token).await {
                    // Challenge exists, check if expired
                    let max_ttl = config.opts.challenge_max_ttl_seconds.unwrap_or(3600);
                    if let Ok(true) = storage.is_challenge_expired(&challenge_token, max_ttl).await {
                        info!("Existing challenge for token {} is expired (TTL: {}s), will be replaced", challenge_token, max_ttl);
                    }
                }

                if let Err(e) = cert_init_server(config, &challenge, &key_auth).await {
                    warn!("Failed to write challenge file for HTTP-01 challenge: {}. Skipping HTTP-01 challenge.", e);
                    continue;
                }
            }
            instant_acme::ChallengeType::Dns01 => {
                // For wildcard domains (*.example.com), strip the wildcard prefix
                // The DNS-01 challenge should be at _acme-challenge.example.com, not _acme-challenge.*.example.com
                let domain_for_dns = domain.strip_prefix("*.").unwrap_or(&domain);
                let dns_record = format!("_acme-challenge.{}", domain_for_dns);
                let dns_value = challenge.key_authorization().dns_value();

                info!("DNS-01 challenge for domain '{}':", domain);
                info!("  {} IN TXT {}", dns_record, dns_value);

                // Check if existing DNS challenge is expired and clean it up
                let storage = StorageFactory::create_default(config)?;
                if let Ok(Some(_)) = storage.get_dns_challenge_timestamp(&domain).await {
                    // DNS challenge exists, check if expired
                    let max_ttl = config.opts.challenge_max_ttl_seconds.unwrap_or(3600);
                    if let Ok(true) = storage.is_dns_challenge_expired(&domain, max_ttl).await {
                        info!("Existing DNS challenge for domain {} is expired (TTL: {}s), will be replaced", domain, max_ttl);
                    }
                }

                // Save DNS challenge code to storage (Redis or file)
                if let Err(e) = storage.write_dns_challenge(&domain, &dns_record, &dns_value).await {
                    warn!("Failed to save DNS challenge code to storage: {}", e);
                }

                info!("Waiting for DNS record to propagate...");

                // Automatically check DNS records
                let max_attempts = config.opts.dns_lookup_max_attempts.unwrap_or(100);
                let delay_seconds = config.opts.dns_lookup_delay_seconds.unwrap_or(10);
                let dns_ready = check_dns_txt_record(&dns_record, &dns_value, max_attempts, delay_seconds).await;

                if !dns_ready {
                    let error_msg = format!("DNS record not found after checking for domain {}. Record: {} IN TXT {}", domain, dns_record, dns_value);
                    warn!("{}. Please verify the DNS record is set correctly.", error_msg);
                    let storage = StorageFactory::create_default(config)?;
                    if let Err(record_err) = storage.record_failure(&error_msg).await {
                        warn!("Failed to record failure: {}", record_err);
                    }
                    return Ok(());
                }

                info!("DNS record found! Proceeding with challenge validation...");
            }
            instant_acme::ChallengeType::TlsAlpn01 => todo!("TLS-ALPN-01 is not supported"),
            _ => {
                let error_msg = format!("Unsupported challenge type: {:?}", challenge_type);
                warn!("{}", error_msg);
                let storage = StorageFactory::create_default(config)?;
                if let Err(record_err) = storage.record_failure(&error_msg).await {
                    warn!("Failed to record failure: {}", record_err);
                }
                return Ok(());
            }
        }

        // Notify ACME server to validate
        info!("Domain '{}': Notifying ACME server to validate challenge", domain);
        challenge.set_ready().await
            .with_context(|| format!("Failed to set challenge ready for domain {}", domain))?;
        challenges_set.push(domain);
    }

    if challenges_set.is_empty() {
        let error_msg = format!("All domains failed challenge setup for domain {}", config.opts.domain);
        warn!("{}", error_msg);
        let storage = StorageFactory::create_default(config)?;
        if let Err(record_err) = storage.record_failure(&error_msg).await {
            warn!("Failed to record failure: {}", record_err);
        }
        return Ok(());
    }

    // Exponentially back off until the order becomes ready or invalid.
    let mut tries = 0u8;
    let state = loop {
        let state = match order.refresh().await {
            Ok(s) => s,
            Err(e) => {
                if tries >= 10 {
                    let error_msg = format!("Order refresh failed after {} attempts: {}", tries, e);
                    warn!("{}", error_msg);
                    let storage = StorageFactory::create_default(config)?;
                    if let Err(record_err) = storage.record_failure(&error_msg).await {
                        warn!("Failed to record failure: {}", record_err);
                    }
                    return Ok(());
                }
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        info!("Order state: {:#?}", state);
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
            break state;
        }

        tries += 1;
        if tries >= 10 {
            let error_msg = format!("Giving up: order is not ready after {} attempts for domain {}", tries, config.opts.domain);
            warn!("{}", error_msg);
            let storage = StorageFactory::create_default(config)?;
            if let Err(record_err) = storage.record_failure(&error_msg).await {
                warn!("Failed to record failure: {}", record_err);
            }
            return Ok(());
        }

        let delay = std::time::Duration::from_secs(2 + tries as u64);
        info!("order is not ready, waiting {delay:?}");
        tokio::time::sleep(delay).await;
    };

    if state.status == OrderStatus::Invalid {
        // Try to get more details about why the order is invalid
        let mut error_details = Vec::new();
        if let Some(error) = &state.error {
            error_details.push(format!("Order error: {:?}", error));
        }

        // Fetch authorization details from ACME server if state is None
        for auth in &state.authorizations {
            if let Some(auth_state) = &auth.state {
                // Check authorization status for more details
                match &auth_state.status {
                    instant_acme::AuthorizationStatus::Invalid => {
                        error_details.push(format!("Authorization {} is invalid", auth.url));
                    }
                    instant_acme::AuthorizationStatus::Expired => {
                        error_details.push(format!("Authorization {} expired", auth.url));
                    }
                    instant_acme::AuthorizationStatus::Revoked => {
                        error_details.push(format!("Authorization {} revoked", auth.url));
                    }
                    _ => {}
                }
            } else {
                // Authorization state is None - this means the authorization details weren't included in the order state
                // We can't fetch it again because order.authorizations() was already consumed
                // Log the URL so the user can check it manually
                warn!("Authorization state is None for {}. This usually means the authorization failed or expired. Check the authorization URL for details.", auth.url);
                error_details.push(format!("Authorization {} state unavailable (check URL for details)", auth.url));
            }
        }

        let error_msg = if error_details.is_empty() {
            format!("Order is invalid but no error details available. Order state: {:#?}", state)
        } else {
            format!("Order is invalid. Details: {}", error_details.join("; "))
        };
        warn!("{}", error_msg);
        let storage = StorageFactory::create_default(config)?;
        if let Err(record_err) = storage.record_failure(&error_msg).await {
            warn!("Failed to record failure: {}", record_err);
        }
        return Ok(());
    }

    // If the order is ready, we can provision the certificate.
    // Finalize the order - this will generate a CSR and return the private key PEM.
    let private_key_pem = order.finalize().await
        .context("Failed to finalize ACME order")?;

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut tries = 1u8;

    let cert_chain_pem = loop {
        match order.certificate().await {
            Ok(Some(cert_chain_pem)) => {
                info!("Certificate ready!");
                break cert_chain_pem;
            }
            Ok(None) => {
                if tries > 10 {
                    let error_msg = format!("Giving up: certificate is still not ready after {} attempts", tries);
                    let storage = StorageFactory::create_default(config)?;
                    if let Err(record_err) = storage.record_failure(&error_msg).await {
                        warn!("Failed to record failure: {}", record_err);
                    }
                    return Err(anyhow!("{}", error_msg));
                }
                tries += 1;
                info!("Certificate not ready yet...");
                continue;
            }
            Err(e) => {
                let error_msg = format!("Error getting certificate: {}", e);
                let storage = StorageFactory::create_default(config)?;
                if let Err(record_err) = storage.record_failure(&error_msg).await {
                    warn!("Failed to record failure: {}", record_err);
                }
                return Err(anyhow!("{}", error_msg));
            }
        }
    };

    write_certs(config, cert_chain_pem, private_key_pem).await
        .context("Failed to write certificates to storage")?;

    // Clear any previous failure records since certificate was successfully generated
    let storage = StorageFactory::create_default(config)?;
    if let Err(clear_err) = storage.clear_failure().await {
        warn!("Failed to clear failure record: {}", clear_err);
    }

    info!("HTTPS TLS Cert init successful! Certificate written to storage.");

    Ok(())
}

async fn write_certs(
    config: &crate::config::Config,
    cert_chain_pem: String,
    private_key_pem: String,
) -> AtomicServerResult<()> {
    let storage_type = if let Some(storage_type_str) = &config.opts.storage_type {
        storage_type_str.clone()
    } else {
        "file".to_string()
    };
    info!("Creating storage backend: {}", storage_type);
    let storage = StorageFactory::create_default(config)?;
    info!("Storage backend created successfully");

    info!("Writing TLS certificates to storage (certbot-style)");

    // Parse the certificate chain to separate cert from chain
    // The cert_chain_pem contains the domain cert first, followed by intermediate certs
    // It's already in PEM format, so we split it by "-----BEGIN CERTIFICATE-----"
    let cert_parts: Vec<String> = cert_chain_pem
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("-----BEGIN CERTIFICATE-----{}", s))
        .collect();

    if cert_parts.is_empty() {
        return Err(anyhow!("No certificates found in chain"));
    }

    // First certificate is the domain certificate
    let domain_cert_pem = cert_parts[0].trim().to_string();

    // Remaining certificates form the chain
    let chain_pem = if cert_parts.len() > 1 {
        cert_parts[1..].join("\n")
    } else {
        String::new()
    };

    info!("Writing certificate to storage backend...");
    storage.write_certs(
        domain_cert_pem.as_bytes(),
        chain_pem.as_bytes(),
        private_key_pem.as_bytes(),
    ).await
        .context("Failed to write certificates to storage backend")?;
    info!("Certificates written successfully to storage backend");

    storage.write_created_at(chrono::Utc::now()).await
        .context("Failed to write created_at timestamp")?;
    info!("Created_at timestamp written successfully");

    Ok(())
}

/// Start HTTP server for ACME challenge requests
/// This server only serves ACME challenge files and keeps running indefinitely
pub async fn start_http_server(app_config: &crate::config::AppConfig) -> AtomicServerResult<()> {
    let address = format!("{}:{}", app_config.server.ip, app_config.server.port);
    info!("Starting HTTP server for ACME challenges at {}", address);
    info!("Server will only accept ACME challenge requests at /.well-known/acme-challenge/*");
    info!("Certificate expiration check endpoints:");
    info!("  - GET /cert/expiration - Check all domains");
    info!("  - GET /cert/expiration/{{domain}} - Check specific domain");
    info!("To stop the program, press Ctrl+C");

    // Use the base storage path for serving ACME challenges
    // Challenges are stored in a shared location: https_path/well-known/acme-challenge/
    let base_static_path = std::path::PathBuf::from(&app_config.storage.https_path);

    // Build the path to the well-known/acme-challenge directory
    // Files are stored at: base_path/well-known/acme-challenge/{token}
    let mut challenge_static_path = base_static_path.clone();
    challenge_static_path.push("well-known");
    challenge_static_path.push("acme-challenge");

    // Ensure the challenge directory exists (required for actix_files::Files)
    // Even when using Redis storage, challenge files are still written to filesystem for HTTP-01
    tokio::fs::create_dir_all(&challenge_static_path)
        .await
        .with_context(|| format!("Failed to create challenge static path directory: {:?}", challenge_static_path))?;

    let base_https_path = base_static_path.clone();
    let app_config_data = web::Data::new(app_config.clone());
    let base_path_data = web::Data::new(base_https_path);

    // Create HTTP server that only serves ACME challenge files
    // The server will serve from any domain's challenge directory
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_config_data.clone())
            .app_data(base_path_data.clone())
            .service(
                // Serve ACME challenges from the challenge directory
                // URL: /.well-known/acme-challenge/{token}
                // File: base_path/well-known/acme-challenge/{token}
                // The Files service maps the URL path to the file system path
                actix_files::Files::new("/.well-known/acme-challenge", challenge_static_path.clone())
                    .prefer_utf8(true),
            )
            .route(
                "/cert/expiration",
                web::get().to(check_all_certs_expiration_handler),
            )
            .route(
                "/cert/expiration/{domain}",
                web::get().to(check_cert_expiration_handler),
            )
            // Reject all other requests with 404
            .default_service(web::route().to(|| async {
                HttpResponse::NotFound().body("Not Found")
            }))
    })
    .bind(&address)
    .with_context(|| format!("Failed to bind HTTP server to {}", address))?;

    info!("HTTP server started successfully at {}", address);

    // Keep the server running indefinitely
    server.run().await
        .with_context(|| "HTTP server error")?;

    Ok(())
}
