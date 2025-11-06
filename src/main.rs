use clap::Parser;
use ssl_storage::{request_cert, should_renew_certs_check, AppConfig, DomainReaderFactory};
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

