use clap::Parser;
use ssl_storage::{request_cert, should_renew_certs_check, AppConfig, DomainReaderFactory};
use std::path::PathBuf;
use tracing_subscriber;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "ssl-storage")]
#[command(about = "ACME/Let's Encrypt certificate management tool")]
struct Args {
    /// Path to config.yaml file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider (required for rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Load configuration from YAML file
    let app_config = AppConfig::from_file(&args.config)
        .map_err(|e| format!("Failed to load config from {}: {}", args.config, e))?;

    info!("Loaded configuration from {}", args.config);

    // Create domain reader based on config
    let domain_reader = DomainReaderFactory::create(&app_config.domains)
        .map_err(|e| format!("Failed to create domain reader: {}", e))?;

    // Read domains from configured source
    let domains = domain_reader.read_domains().await
        .map_err(|e| format!("Failed to read domains: {}", e))?;

    info!("Found {} domain(s) to process", domains.len());

    if domains.is_empty() {
        warn!("No domains found in source. Exiting.");
        return Ok(());
    }

    let https_path = PathBuf::from(&app_config.storage.https_path);

    // Process each domain
    for domain_config in domains.iter() {
        info!("Processing domain: {}", domain_config.domain);

        // Create domain-specific config
        let domain_cfg = app_config.create_domain_config(domain_config, https_path.clone());

        // Check if certificates need renewal
        if should_renew_certs_check(&domain_cfg).await? {
            info!("Requesting new certificate for {}...", domain_config.domain);
            request_cert(&domain_cfg).await?;
            info!("Certificate obtained successfully for {}!", domain_config.domain);
        } else {
            info!("Certificates are still valid for {}.", domain_config.domain);
        }
    }

    // Keep the program running after certificate operations
    // Start HTTP server for ACME challenges
    info!("Starting HTTP server for ACME challenges...");
    ssl_storage::start_http_server(&app_config).await?;

    Ok(())
}

