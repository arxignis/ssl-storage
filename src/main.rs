use clap::Parser;
use ssl_storage::{request_cert, should_renew_certs_check, should_retry_failed_cert, AppConfig, DomainReaderFactory, StorageFactory};
use std::path::PathBuf;
use tracing::{info, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use std::sync::{Arc, Mutex};
use syslog::{Facility as SyslogFacility, Formatter3164, Severity};
use daemonize::Daemonize;

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

    let args = Args::parse();

    // Load configuration from YAML file
    let app_config = AppConfig::from_file(&args.config)
        .map_err(|e| format!("Failed to load config from {}: {}", args.config, e))?;

    // Daemonize if configured (must be done before initializing logging)
    if app_config.server.daemon {
        daemonize_process(&app_config)?;
    }

    // Initialize logging based on configuration
    init_logging(&app_config)?;

    info!("Loaded configuration from {}", args.config);

    info!("Starting HTTP server for ACME challenges...");
    let app_config_clone = app_config.clone();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = ssl_storage::start_http_server(&app_config_clone).await {
            warn!("HTTP server error: {}", e);
        }
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Create domain reader based on config (wrap in Arc to share with periodic task)
    let domain_reader = Arc::new(
        DomainReaderFactory::create(&app_config.domains)
            .map_err(|e| format!("Failed to create domain reader: {}", e))?
    );

    // Read domains from configured source
    let domains = domain_reader.read_domains().await
        .map_err(|e| format!("Failed to read domains: {}", e))?;

    info!("Found {} domain(s) to process", domains.len());

    if domains.is_empty() {
        warn!("No domains found in source. Exiting.");
        return Ok(());
    }

    let https_path = PathBuf::from(&app_config.storage.https_path);

    // Start HTTP server for ACME challenges BEFORE processing certificates
    // The server must be running to serve challenge files during certificate requests


    // Process each domain initially
    for domain_config in domains.iter() {
        info!("Processing domain: {}", domain_config.domain);

        // Create domain-specific config
        let domain_cfg = app_config.create_domain_config(domain_config, https_path.clone());

        // Ensure certificate hash exists for existing certificates (backward compatibility)
        // This will generate hashes for certificates that were created before hash feature was added
        let storage = StorageFactory::create_default(&domain_cfg)?;
        if storage.cert_exists().await {
            if let Err(e) = storage.get_certificate_hash().await {
                warn!("Failed to get or generate certificate hash for {}: {}", domain_config.domain, e);
            } else {
                info!("Certificate hash verified/generated for {}", domain_config.domain);
            }
        }

        // Check if certificates need renewal
        if should_renew_certs_check(&domain_cfg).await? {
            info!("Requesting new certificate for {}...", domain_config.domain);
            if let Err(e) = request_cert(&domain_cfg).await {
                warn!("Failed to request certificate for {}: {}", domain_config.domain, e);
            } else {
                info!("Certificate obtained successfully for {}!", domain_config.domain);
            }
        } else {
            info!("Certificates are still valid for {}.", domain_config.domain);
        }
    }

    // Periodic recheck loop for failed certificates
    if app_config.acme.retry.enable_periodic_check {
        info!("Periodic recheck enabled. Checking every {} seconds.", app_config.acme.retry.check_interval_seconds);

        let check_interval = tokio::time::Duration::from_secs(app_config.acme.retry.check_interval_seconds);
        let app_config_clone = app_config.clone();
        let https_path_clone = https_path.clone();

        // Clone the domain reader Arc to share with periodic task
        let domain_reader_clone = Arc::clone(&domain_reader);

        let periodic_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                info!("Starting periodic certificate recheck...");

                // Re-read domains using the shared reader (will use cached data if available)
                let domains = match domain_reader_clone.read_domains().await {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("Failed to read domains during periodic check: {}", e);
                        continue;
                    }
                };

                // Clean up expired challenges
                let max_ttl = app_config_clone.acme.challenge_max_ttl_seconds;
                for domain_config in domains.iter() {
                    let domain_cfg = app_config_clone.create_domain_config(domain_config, https_path_clone.clone());
                    let storage = match ssl_storage::StorageFactory::create_default(&domain_cfg) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to create storage for {}: {}", domain_config.domain, e);
                            continue;
                        }
                    };
                    if let Err(e) = storage.cleanup_expired_challenges(max_ttl).await {
                        warn!("Failed to cleanup expired challenges for {}: {}", domain_config.domain, e);
                    }
                }

                for domain_config in domains.iter() {
                    let domain_cfg = app_config_clone.create_domain_config(domain_config, https_path_clone.clone());

                    // Check if certificate exists and is valid
                    let needs_renewal = match should_renew_certs_check(&domain_cfg).await {
                        Ok(needs) => needs,
                        Err(e) => {
                            warn!("Failed to check certificate renewal for {}: {}", domain_config.domain, e);
                            continue;
                        }
                    };

                    // Check if there's a failed certificate that should be retried
                    let should_retry = match should_retry_failed_cert(&domain_cfg, &app_config_clone.acme.retry).await {
                        Ok(retry) => retry,
                        Err(e) => {
                            warn!("Failed to check retry status for {}: {}", domain_config.domain, e);
                            false
                        }
                    };

                    if needs_renewal || should_retry {
                        if should_retry {
                            info!("Retrying failed certificate generation for {}...", domain_config.domain);
                        } else {
                            info!("Requesting new certificate for {}...", domain_config.domain);
                        }

                        if let Err(e) = request_cert(&domain_cfg).await {
                            warn!("Failed to request certificate for {}: {}", domain_config.domain, e);
                        } else {
                            info!("Certificate obtained successfully for {}!", domain_config.domain);
                        }
                    }
                }

                info!("Periodic certificate recheck complete. Next check in {} seconds.", app_config_clone.acme.retry.check_interval_seconds);
            }
        });

        // Keep the program running - wait for both the HTTP server and periodic loop
        info!("Certificate processing complete. HTTP server and periodic recheck will continue running.");
        tokio::select! {
            _ = server_handle => {},
            _ = periodic_handle => {},
        }
    } else {
        // Keep the program running - wait for the HTTP server
        info!("Certificate processing complete. HTTP server will continue running.");
        server_handle.await?;
    }

    Ok(())
}

fn init_logging(config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Create env filter from config or RUST_LOG env var
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    match config.logging.output.as_str() {
        "syslog" => {
            // Parse syslog facility
            let facility = parse_syslog_facility(&config.logging.syslog_facility)?;

            // Initialize syslog writer
            let formatter = Formatter3164 {
                facility,
                hostname: None,
                process: config.logging.syslog_identifier.clone(),
                pid: std::process::id(),
            };

            let writer = syslog::unix(formatter)
                .map_err(|e| format!("Failed to connect to syslog: {}", e))?;

            let syslog_layer = SyslogLayer::new(writer);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(syslog_layer)
                .init();

            info!("Logging initialized: syslog (facility: {})", config.logging.syslog_facility);
        }
        "journald" => {
            // Initialize journald layer
            let journald_layer = tracing_journald::layer()
                .map_err(|e| format!("Failed to initialize journald: {}", e))?;

            tracing_subscriber::registry()
                .with(env_filter)
                .with(journald_layer)
                .init();

            info!("Logging initialized: journald");
        }
        "stdout" | _ => {
            // Default to stdout
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();

            if config.logging.output != "stdout" {
                warn!("Unknown logging output '{}', defaulting to stdout", config.logging.output);
            }
        }
    }

    Ok(())
}

type SyslogWriter = syslog::Logger<syslog::LoggerBackend, Formatter3164>;

fn parse_syslog_facility(facility: &str) -> Result<SyslogFacility, Box<dyn std::error::Error>> {
    match facility.to_lowercase().as_str() {
        "kern" | "kernel" => Ok(SyslogFacility::LOG_KERN),
        "user" => Ok(SyslogFacility::LOG_USER),
        "mail" => Ok(SyslogFacility::LOG_MAIL),
        "daemon" => Ok(SyslogFacility::LOG_DAEMON),
        "auth" => Ok(SyslogFacility::LOG_AUTH),
        "syslog" => Ok(SyslogFacility::LOG_SYSLOG),
        "lpr" => Ok(SyslogFacility::LOG_LPR),
        "news" => Ok(SyslogFacility::LOG_NEWS),
        "uucp" => Ok(SyslogFacility::LOG_UUCP),
        "cron" => Ok(SyslogFacility::LOG_CRON),
        "authpriv" => Ok(SyslogFacility::LOG_AUTHPRIV),
        "ftp" => Ok(SyslogFacility::LOG_FTP),
        "local0" => Ok(SyslogFacility::LOG_LOCAL0),
        "local1" => Ok(SyslogFacility::LOG_LOCAL1),
        "local2" => Ok(SyslogFacility::LOG_LOCAL2),
        "local3" => Ok(SyslogFacility::LOG_LOCAL3),
        "local4" => Ok(SyslogFacility::LOG_LOCAL4),
        "local5" => Ok(SyslogFacility::LOG_LOCAL5),
        "local6" => Ok(SyslogFacility::LOG_LOCAL6),
        "local7" => Ok(SyslogFacility::LOG_LOCAL7),
        _ => Err(format!("Unknown syslog facility: {}", facility).into()),
    }
}

// Custom syslog layer for tracing
struct SyslogLayer {
    writer: Arc<Mutex<SyslogWriter>>,
}

impl SyslogLayer {
    fn new(writer: SyslogWriter) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer))
        }
    }
}

impl<S> Layer<S> for SyslogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut message = String::new();
        let mut visitor = MessageVisitor(&mut message);
        event.record(&mut visitor);

        if let Ok(mut writer) = self.writer.lock() {
            let severity = match *event.metadata().level() {
                Level::ERROR => Severity::LOG_ERR,
                Level::WARN => Severity::LOG_WARNING,
                Level::INFO => Severity::LOG_INFO,
                Level::DEBUG => Severity::LOG_DEBUG,
                Level::TRACE => Severity::LOG_DEBUG,
            };

            // Logger trait from syslog uses `err`, `warning`, `info`, etc.
            match severity {
                Severity::LOG_ERR => { let _ = writer.err(message); },
                Severity::LOG_WARNING => { let _ = writer.warning(message); },
                Severity::LOG_INFO => { let _ = writer.info(message); },
                Severity::LOG_DEBUG => { let _ = writer.debug(message); },
                _ => { let _ = writer.info(message); },
            }
        }
    }
}

struct MessageVisitor<'a>(&'a mut String);

impl<'a> tracing::field::Visit for MessageVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.0, "{:?}", value);
        } else {
            if !self.0.is_empty() {
                self.0.push_str(", ");
            }
            let _ = write!(self.0, "{}={:?}", field.name(), value);
        }
    }
}

fn daemonize_process(config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut daemonize = Daemonize::new();

    // Set PID file if configured
    if let Some(pid_file) = &config.server.pid_file {
        daemonize = daemonize.pid_file(pid_file);
    }

    // Set working directory if configured
    if let Some(work_dir) = &config.server.working_directory {
        daemonize = daemonize.working_directory(work_dir);
    }

    // Set user/group to current user (safer than running as root)
    daemonize = daemonize
        .user(std::env::var("USER").unwrap_or_else(|_| "root".to_string()).as_str())
        .group(std::env::var("USER").unwrap_or_else(|_| "root".to_string()).as_str());

    // Start the daemon
    daemonize.start()
        .map_err(|e| format!("Failed to daemonize: {}", e))?;

    Ok(())
}

