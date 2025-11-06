# SSL Storage

A Rust-based ACME/Let's Encrypt certificate management tool with support for multiple storage backends and domain sources. Automatically manages SSL/TLS certificates, handles renewals, and supports both HTTP-01 and DNS-01 challenges.

## Features

- **Automatic Certificate Management**: Request, renew, and manage SSL/TLS certificates from Let's Encrypt
- **Multiple Storage Backends**:
  - File system storage (Certbot-style with `live/` and `archive/` directories)
    - 100% compatible with certbot
  - Redis storage for distributed deployments
- **Multiple Domain Sources**:
  - JSON file
  - Redis
  - HTTP endpoint
- **Challenge Types**:
  - HTTP-01 challenge for standard domains
  - DNS-01 challenge for wildcard domains (automatic detection)
- **Distributed Locking**: Redis-based distributed locks prevent race conditions when multiple instances run simultaneously
- **Automatic Renewal**: Checks certificate expiration and automatically renews when needed
- **REST API**: HTTP endpoints for checking certificate expiration status
- **DNS Propagation Checking**: Automatically verifies DNS TXT records for DNS-01 challenges
- **Flexible Logging**: Support for stdout, syslog, and journald with configurable log levels

## Installation

### Prerequisites

- Rust 1.70+ (with edition 2024)
- Access to Let's Encrypt (production or staging)
- For DNS-01 challenges: DNS provider that supports TXT record management
- For Redis storage: Redis server (local or remote)

### Build from Source

```bash
git clone <repository-url>
cd ssl-storage
cargo build --release
```

The binary will be available at `target/release/ssl-storage`.

## Configuration

Create a `config.yaml` file in the project root:

```yaml
# Server settings
server:
  ip: "0.0.0.0"
  port: 80
  # Run as daemon (background process)
  daemon: false
  # PID file path (for daemon mode)
  pid_file: "/var/run/ssl-storage.pid"

# Logging settings
logging:
  # Logging output: "stdout", "syslog", or "journald"
  output: "stdout"
  # Log level: trace, debug, info, warn, error
  level: "info"
  # Syslog facility (for syslog output): daemon, user, local0-local7, etc.
  syslog_facility: "daemon"
  # Syslog identifier/tag (for syslog output)
  syslog_identifier: "ssl-storage"

# Certificate storage settings
storage:
  # Storage backend type: "file" or "redis"
  type: "redis"
  # Base path for certificate storage (used for file storage)
  https_path: "certs"
  # Redis URL (used for redis storage, can also be set via REDIS_URL env var)
  redis_url: "redis://127.0.0.1:6379"
  # Lock TTL in seconds (for Redis distributed lock, default: 900 = 15 minutes)
  lock_ttl_seconds: 900

# ACME/Let's Encrypt settings
acme:
  # Default email for Let's Encrypt registration
  email: "your-email@example.com"
  # Use staging server (for testing)
  development: false
  # DNS-01 challenge lookup settings
  dns_lookup:
    # Maximum number of attempts to check DNS record
    max_attempts: 100
    # Delay between attempts in seconds
    delay_seconds: 10

# Domain source configuration
domains:
  # Source type: "file", "redis", or "http"
  source: "file"
  # File path (for file source)
  file_path: "domains.json"
  # Redis key (for redis source)
  redis_key: "ssl-storage:domains"
  # Redis URL (for redis source, can also be set via REDIS_URL env var)
  redis_url: "redis://127.0.0.1:6379"
  # HTTP endpoint (for http source)
  http_url: "http://localhost:8080/domains"
  # HTTP refresh interval in seconds (for http source)
  http_refresh_interval: 300
```

## Domain Configuration

### File Source (`domains.json`)

```json
[
  {
    "domain": "example.com",
    "email": "admin@example.com",
    "dns": false,
    "wildcard": false
  },
  {
    "domain": "*.example.com",
    "email": "admin@example.com",
    "dns": true,
    "wildcard": true
  }
]
```

### Redis Source

Store domains as JSON array in Redis at the configured key:

```bash
redis-cli SET "ssl-storage:domains" '[{"domain":"example.com","email":"admin@example.com","dns":false,"wildcard":false}]'
```

### HTTP Source

Provide a JSON endpoint that returns the same format as the file source.

## Usage

### Basic Usage

```bash
ssl-storage --config config.yaml
```

### Command Line Options

- `--config, -c`: Path to config.yaml file (default: `config.yaml`)

### Automated Renewal with Cron

You can set up a cron job to automatically check and renew certificates periodically. The application will automatically check certificate expiration and renew certificates when needed.

#### Example Cron Job

Add the following to your crontab (`crontab -e`) to check and renew certificates daily at 2 AM:

```bash
# Check and renew SSL certificates daily at 2 AM
0 2 * * * /path/to/ssl-storage --config /path/to/config.yaml >> /var/log/ssl-storage.log 2>&1
```

#### More Frequent Checks

For more frequent checks (e.g., every 6 hours):

```bash
# Check and renew SSL certificates every 6 hours
0 */6 * * * /path/to/ssl-storage --config /path/to/config.yaml >> /var/log/ssl-storage.log 2>&1
```

#### Weekly Check

For weekly checks (e.g., every Monday at 3 AM):

```bash
# Check and renew SSL certificates weekly on Monday at 3 AM
0 3 * * 1 /path/to/ssl-storage --config /path/to/config.yaml >> /var/log/ssl-storage.log 2>&1
```

#### Notes

- The application will automatically check certificate expiration and only renew certificates that are close to expiring
- If using Redis storage with distributed locking, multiple cron jobs can run simultaneously without conflicts

#### Running as a Service

Alternatively, you can run `ssl-storage` as a long-running service that continuously monitors certificates. The application will keep running and serve ACME challenges:

```bash
# Run as a service (keeps running and serves ACME challenges)
ssl-storage --config config.yaml
```

### How It Works

1. **Startup**: The application loads configuration from `config.yaml`
2. **Domain Loading**: Reads domains from the configured source (file, Redis, or HTTP)
3. **Certificate Check**: For each domain, checks if a certificate exists and if it needs renewal
4. **Certificate Request**: If needed, requests a new certificate from Let's Encrypt
   - For wildcard domains (`*.example.com`), automatically uses DNS-01 challenge
   - For standard domains, uses HTTP-01 challenge by default
5. **Storage**: Saves certificates to the configured storage backend
6. **HTTP Server**: Starts an HTTP server to serve ACME challenges and provide API endpoints

### Storage Backends

#### File Storage

Certificates are stored in a Certbot-style directory structure:

```
certs/
└── example.com/
    ├── archive/
    │   ├── cert1.pem
    │   ├── chain1.pem
    │   ├── fullchain1.pem
    │   └── privkey1.pem
    └── live/
        ├── cert.pem -> ../archive/cert1.pem
        ├── chain.pem -> ../archive/chain1.pem
        ├── fullchain.pem -> ../archive/fullchain1.pem
        └── privkey.pem -> ../archive/privkey1.pem
```

#### Redis Storage

Certificates are stored in Redis with the following key structure:

- `ssl-storage:{domain}:live:cert` - Domain certificate
- `ssl-storage:{domain}:live:chain` - Intermediate chain
- `ssl-storage:{domain}:live:fullchain` - Full chain (cert + chain)
- `ssl-storage:{domain}:live:privkey` - Private key
- `ssl-storage:{domain}:metadata:created_at` - Certificate creation timestamp
- `ssl-storage:{domain}:dns-challenge` - DNS challenge data (JSON)
- `ssl-storage:{domain}:lock` - Distributed lock key

**Note**: Redis storage only keeps the current (live) version. Archived certificates are automatically deleted.

### Distributed Locking

When using Redis storage with multiple instances:

- Each instance attempts to acquire a distributed lock before processing a domain
- Lock TTL is configurable via `storage.lock_ttl_seconds` (default: 900 seconds)
- If a lock cannot be acquired, the instance skips that domain (another instance is processing it)
- Locks are automatically released when processing completes or expires

## API Endpoints

The HTTP server provides the following endpoints:

### Check Certificate Expiration (All Domains)

```bash
GET /cert/expiration
```

**Response**:
```json
[
  {
    "domain": "example.com",
    "exists": true,
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": "2024-04-01T00:00:00Z",
    "days_until_expiry": 30,
    "needs_renewal": false,
    "renewing": false
  }
]
```

### Check Certificate Expiration (Single Domain)

```bash
GET /cert/expiration/{domain}
```

**Response**:
```json
{
  "domain": "example.com",
  "exists": true,
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-04-01T00:00:00Z",
  "days_until_expiry": 30,
  "needs_renewal": false,
  "renewing": false
}
```

**Note**: If a certificate needs renewal, the endpoint automatically starts the renewal process in the background and sets `renewing: true`.

### ACME Challenge Endpoint

```bash
GET /.well-known/acme-challenge/{token}
```

Serves HTTP-01 challenge tokens for Let's Encrypt validation.

## Challenge Types

### HTTP-01 Challenge

- Used for standard domains (non-wildcard)
- Requires the server to be accessible on port 80
- Challenge files are served at `/.well-known/acme-challenge/{token}`

### DNS-01 Challenge

- Automatically used for wildcard domains (`*.example.com`)
- Requires creating a TXT record: `_acme-challenge.example.com IN TXT {challenge_value}`
- The application automatically checks DNS propagation before proceeding
- DNS challenge data is stored in Redis (when using Redis storage) for reference

## Daemon Mode

The application can run as a background daemon process:

```yaml
server:
  daemon: true
  pid_file: "/var/run/ssl-storage.pid"
  working_directory: "/var/lib/ssl-storage"  # Optional
```

**Important notes for daemon mode:**
- When running as daemon, use `syslog` or `journald` for logging (stdout won't be visible)
- The PID file allows you to manage the daemon process
- Ensure the user has write permissions to the PID file location
- The process will fork to background and detach from the terminal

**Managing the daemon:**

```bash
# Start as daemon
ssl-storage --config config.yaml

# Check if running
cat /var/run/ssl-storage.pid
ps aux | grep ssl-storage

# Stop the daemon
kill $(cat /var/run/ssl-storage.pid)

# View logs (if using syslog)
tail -f /var/log/syslog | grep ssl-storage
```

**Example daemon configuration:**

```yaml
server:
  ip: "0.0.0.0"
  port: 80
  daemon: true
  pid_file: "/var/run/ssl-storage.pid"

logging:
  output: "syslog"
  level: "info"
  syslog_facility: "daemon"
  syslog_identifier: "ssl-storage"
```

For production deployments, consider using systemd instead (see Logging section below).

## Logging

The application supports three logging outputs:

### Stdout (Default)

Logs to standard output/error. Suitable for Docker containers and development.

```yaml
logging:
  output: "stdout"
  level: "info"
```

### Syslog

Logs to the system syslog daemon. Ideal for production servers.

```yaml
logging:
  output: "syslog"
  level: "info"
  syslog_facility: "daemon"
  syslog_identifier: "ssl-storage"
```

**Available syslog facilities:**
- `daemon` - System daemons (recommended)
- `user` - User-level messages
- `local0` through `local7` - Custom local use
- `auth`, `authpriv`, `cron`, `ftp`, `kern`, `lpr`, `mail`, `news`, `syslog`, `uucp`

**View syslog messages:**
```bash
# On most Linux systems
tail -f /var/log/syslog | grep ssl-storage

# Or using journalctl
journalctl -f -t ssl-storage
```

### Journald

Logs to systemd's journald. Best for systemd-based systems.

```yaml
logging:
  output: "journald"
  level: "info"
```

**View journald logs:**
```bash
# Follow logs in real-time
journalctl -f -u ssl-storage

# View all logs for the service
journalctl -u ssl-storage

# View logs with specific priority
journalctl -u ssl-storage -p info
```

### Log Levels

Available log levels (from most to least verbose):
- `trace` - Very detailed debugging information
- `debug` - Debugging information
- `info` - Informational messages (recommended)
- `warn` - Warning messages
- `error` - Error messages only

The log level can also be set via the `RUST_LOG` environment variable, which takes precedence over the config file:

```bash
RUST_LOG=debug ssl-storage --config config.yaml
```

## Environment Variables

- `REDIS_URL`: Redis connection URL (overrides config file setting)
- `RUST_LOG`: Log level override (e.g., `trace`, `debug`, `info`, `warn`, `error`)

## Examples

### Single Domain with File Storage

```yaml
storage:
  type: "file"
  https_path: "certs"

domains:
  source: "file"
  file_path: "domains.json"
```

### Multiple Domains with Redis Storage

```yaml
storage:
  type: "redis"
  redis_url: "redis://127.0.0.1:6379"

domains:
  source: "redis"
  redis_key: "ssl-storage:domains"
  redis_url: "redis://127.0.0.1:6379"
```

### Wildcard Domain with DNS-01

```json
{
  "domain": "*.example.com",
  "email": "admin@example.com",
  "dns": true,
  "wildcard": true
}
```

The application will:
1. Detect the wildcard prefix (`*.`)
2. Automatically use DNS-01 challenge
3. Generate the DNS record name: `_acme-challenge.example.com`
4. Wait for DNS propagation
5. Complete the certificate request

## Troubleshooting

### Certificate Request Fails

- Check that your domain is accessible (for HTTP-01)
- Verify DNS records are set correctly (for DNS-01)
- Ensure port 80 is accessible (for HTTP-01)
- Check Let's Encrypt rate limits

### DNS Challenge Not Found

- Verify the TXT record is set: `_acme-challenge.{domain} IN TXT {value}`
- Wait for DNS propagation (can take several minutes)
- Check DNS lookup settings in `config.yaml` (`dns_lookup.max_attempts` and `dns_lookup.delay_seconds`)

### Redis Connection Issues

- Verify Redis URL is correct
- Check network connectivity to Redis server
- Ensure Redis server is running

### Multiple Instances Conflict

- Ensure Redis storage is configured
- Distributed locking will prevent conflicts
- Adjust `lock_ttl_seconds` if certificate requests take longer than expected

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

