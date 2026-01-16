# Mosquitto Certificate Watcher & TLS Probe Daemon

A lightweight, production-grade certificate watcher daemon that monitors certificate availability, rotation, and expiry for Eclipse Mosquitto brokers. The daemon performs active upstream TLS handshake validation and triggers controlled Mosquitto restarts when certificates change.

## Features

- **Certificate Monitoring**: Detects certificate presence, rotation, and expiry
- **TLS Validation**: Performs active upstream TLS handshake probes
- **Controlled Restarts**: Triggers Mosquitto container restarts only when certificates change
- **Debouncing**: Prevents restart loops with stability windows and cooldown periods
- **Non-Root Execution**: Runs as non-root user with Docker socket group access
- **Production Ready**: Static binary, scratch-based container, no runtime dependencies
- **Structured Logging**: JSON-formatted logs for observability

## Design Constraints

- **Language**: Go (golang)
- **Container**: Scratch-based (no shell, no package manager)
- **Static Binary**: CGO disabled
- **Privileges**: Non-root execution
- **Deployment**: Docker Compose compatible, edge/VM/bare-metal ready

## State Machine

The certificate watcher operates using the following state machine:

```
                    ┌─────────────────┐
                    │   INITIALIZE    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  CHECK CERTS    │
                    └────────┬────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
        ┌───────────────┐        ┌───────────────┐
        │ CERTS MISSING │        │ CERTS FOUND   │
        └───────┬───────┘        └───────┬───────┘
                │                         │
                │                         ▼
                │                ┌─────────────────┐
                │                │  PARSE CERT     │
                │                └────────┬────────┘
                │                         │
                │                         ▼
                │                ┌─────────────────┐
                │                │ VALIDATE CERT   │
                │                └────────┬────────┘
                │                         │
                │            ┌─────────────┴─────────────┐
                │            │                           │
                │            ▼                           ▼
                │    ┌───────────────┐          ┌───────────────┐
                │    │ CERT EXPIRED  │          │ CERT VALID    │
                │    └───────┬───────┘          └───────┬───────┘
                │            │                           │
                │            │                           ▼
                │            │                  ┌─────────────────┐
                │            │                  │ CHECK STABILITY │
                │            │                  └────────┬────────┘
                │            │                           │
                │            │              ┌─────────────┴─────────────┐
                │            │              │                           │
                │            │              ▼                           ▼
                │            │      ┌───────────────┐          ┌───────────────┐
                │            │      │ NOT STABLE    │          │   STABLE      │
                │            │      └───────┬───────┘          └───────┬───────┘
                │            │            │                           │
                │            │            │                           ▼
                │            │            │                  ┌─────────────────┐
                │            │            │                  │ CHECK COOLDOWN  │
                │            │            │                  └────────┬────────┘
                │            │            │                           │
                │            │            │              ┌─────────────┴─────────────┐
                │            │            │              │                           │
                │            │            │              ▼                           ▼
                │            │            │      ┌───────────────┐          ┌───────────────┐
                │            │            │      │ IN COOLDOWN   │          │ READY         │
                │            │            │      └───────┬───────┘          └───────┬───────┘
                │            │            │            │                           │
                │            │            │            │                           ▼
                │            │            │            │                  ┌─────────────────┐
                │            │            │            │                  │ CHECK HASH      │
                │            │            │            │                  └────────┬────────┘
                │            │            │            │                           │
                │            │            │            │              ┌─────────────┴─────────────┐
                │            │            │            │              │                           │
                │            │            │            │              ▼                           ▼
                │            │            │            │      ┌───────────────┐          ┌───────────────┐
                │            │            │            │      │ HASH UNCHANGED│          │ HASH CHANGED  │
                │            │            │            │      └───────┬───────┘          └───────┬───────┘
                │            │            │            │            │                           │
                │            │            │            │            │                           ▼
                │            │            │            │            │                  ┌─────────────────┐
                │            │            │            │            │                  │ TLS PROBE       │
                │            │            │            │            │                  └────────┬────────┘
                │            │            │            │            │                           │
                │            │            │            │            │                           ▼
                │            │            │            │            │                  ┌─────────────────┐
                │            │            │            │            │                  │ RESTART         │
                │            │            │            │            │                  │ MOSQUITTO       │
                │            │            │            │            │                  └────────┬────────┘
                │            │            │            │            │                           │
                └────────────┴────────────┴────────────┴────────────┴───────────────────────────┘
                                                                              │
                                                                              ▼
                                                                    ┌─────────────────┐
                                                                    │  UPDATE STATE   │
                                                                    │  (lastHash,     │
                                                                    │   lastRestart)  │
                                                                    └────────┬────────┘
                                                                              │
                                                                              ▼
                                                                    ┌─────────────────┐
                                                                    │   WAIT INTERVAL │
                                                                    └────────┬────────┘
                                                                              │
                                                                              └──────────────┐
                                                                                             │
                                                                                             ▼
                                                                                    ┌─────────────────┐
                                                                                    │  CHECK CERTS    │
                                                                                    └─────────────────┘
```

### State Descriptions

1. **INITIALIZE**: Daemon starts, loads configuration
2. **CHECK CERTS**: Scans certificate directory for required files
3. **CERTS MISSING**: Logs warning, continues monitoring
4. **CERTS FOUND**: Proceeds to parse and validate
5. **PARSE CERT**: Extracts certificate information
6. **VALIDATE CERT**: Checks expiry and validity
7. **CERT EXPIRED**: Logs error, does not restart
8. **CERT VALID**: Proceeds to stability check
9. **CHECK STABILITY**: Verifies files haven't changed recently
10. **NOT STABLE**: Waits for stability window
11. **STABLE**: Proceeds to cooldown check
12. **CHECK COOLDOWN**: Verifies restart cooldown has elapsed
13. **IN COOLDOWN**: Suppresses restart, logs reason
14. **READY**: Proceeds to hash comparison
15. **CHECK HASH**: Compares current cert hash with last known
16. **HASH UNCHANGED**: No action needed
17. **HASH CHANGED**: Certificate rotated, proceed to restart
18. **TLS PROBE**: (Optional) Performs upstream TLS handshake
19. **RESTART MOSQUITTO**: Triggers Docker container restart
20. **UPDATE STATE**: Records new hash and restart time
21. **WAIT INTERVAL**: Sleeps until next check cycle

## Configuration

All configuration is done via environment variables.

### Required Variables

- `CERT_DIR`: Directory containing certificates (default: `/certs`)
- `MOSQUITTO_CONTAINER`: Docker container name to restart (default: `eclipse-mosquitto`)
- `UPSTREAM_ADDR`: Upstream broker address for TLS probe (e.g., `broker.example.com:8883`)

### Optional Variables

- `TLS_SNI`: Server Name Indication for TLS (default: extracted from `UPSTREAM_ADDR`)
- `TLS_TIMEOUT`: TLS handshake timeout (default: `5s`)
- `CHECK_INTERVAL`: Interval between certificate checks (default: `5s`)
- `STABILITY_WINDOW`: Time files must be stable before restart (default: `10s`)
- `RESTART_COOLDOWN`: Minimum time between restarts (default: `300s`)
- `EXPIRY_WARN_DAYS`: Days before expiry to warn (default: `14`)
- `DOCKER_SOCK`: Docker socket path (default: `/var/run/docker.sock`)
- `ENABLE_TLS_PROBE`: Enable TLS handshake probes (default: `true`)
- `ENABLE_RESTART`: Enable automatic restarts (default: `true`)
- `LOG_LEVEL`: Logging level: `debug`, `info`, `warn`, `error` (default: `info`)
- `ENABLE_METRICS`: Enable Prometheus metrics endpoint (default: `false`)
- `METRICS_PORT`: Port for metrics HTTP server (default: `9090`)

## Prometheus Metrics

When `ENABLE_METRICS=true`, the daemon exposes Prometheus metrics on `http://:METRICS_PORT/metrics`.

### Available Metrics

- `cert_days_remaining` (gauge): Number of days until certificate expires
- `tls_probe_success_total` (counter): Total number of successful TLS handshake probes
- `tls_probe_failure_total` (counter): Total number of failed TLS handshake probes
- `mosquitto_restarts_total` (counter): Total number of Mosquitto container restarts triggered
- `restart_suppressed_total` (counter): Total number of restarts suppressed due to cooldown or stability window

### Example Metrics Output

```
# HELP cert_days_remaining Number of days until certificate expires
# TYPE cert_days_remaining gauge
cert_days_remaining 350

# HELP tls_probe_success_total Total number of successful TLS handshake probes
# TYPE tls_probe_success_total counter
tls_probe_success_total 42

# HELP tls_probe_failure_total Total number of failed TLS handshake probes
# TYPE tls_probe_failure_total counter
tls_probe_failure_total 2

# HELP mosquitto_restarts_total Total number of Mosquitto container restarts triggered
# TYPE mosquitto_restarts_total counter
mosquitto_restarts_total 3

# HELP restart_suppressed_total Total number of restarts suppressed due to cooldown or stability window
# TYPE restart_suppressed_total counter
restart_suppressed_total 1
```

### Prometheus Scraping Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'mosquitto-cert-watcher'
    static_configs:
      - targets: ['mosquitto-cert-watcher:9090']
```

## Certificate Files

The watcher expects the following files in `CERT_DIR`:

- `ca.crt`: CA certificate
- `client.crt`: Client certificate
- `client.key`: Client private key

All files must exist and be non-empty. The private key is not read for security reasons; only existence and size are checked.

## Building

### Prerequisites

- Go 1.21 or later
- Docker (for container builds)

### Local Build

```bash
# Build for current platform
make build

# Build for Linux AMD64
make build-linux-amd64

# Build for Linux ARM64
make build-linux-arm64
```

### Docker Build

```bash
# Build Docker image
make docker

# Or manually
docker build -t mosquitto-cert-watcher:latest .
```

## Deployment

### Docker Compose

Example `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mosquitto-cert-watcher:
    image: pratexonexus.pratexo.com/mosquitto-cert-watcher:1.0.0
    container_name: mosquitto-cert-watcher
    restart: always

    user: "1000:998"   # ptx UID : docker GID

    environment:
      CERT_DIR: /certs
      MOSQUITTO_CONTAINER: eclipse-mosquitto
      UPSTREAM_ADDR: broker.example.com:8883
      TLS_SNI: broker.example.com
      CHECK_INTERVAL: 5s
      STABILITY_WINDOW: 10s
      RESTART_COOLDOWN: 300s
      EXPIRY_WARN_DAYS: 14
      ENABLE_TLS_PROBE: "true"
      ENABLE_RESTART: "true"
      LOG_LEVEL: info
      ENABLE_METRICS: "true"
      METRICS_PORT: "9090"

    ports:
      - "9090:9090"  # Prometheus metrics endpoint

    volumes:
      - /usr/local/share/ca-certificates/pratexo/rabbitmq:/certs:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro

    networks:
      - pratexo
```

### Docker Socket Access

The container needs access to the Docker socket to restart Mosquitto. Ensure:

1. The Docker socket is mounted: `/var/run/docker.sock:/var/run/docker.sock:ro`
2. The container runs with a user in the `docker` group (typically GID 998)
3. The socket has group read permissions: `chmod 660 /var/run/docker.sock`

## Logging

The daemon emits structured JSON logs:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "component": "cert",
  "event": "cert_parsed",
  "details": {
    "subject": "CN=client.example.com",
    "issuer": "CN=CA.example.com",
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z",
    "days_remaining": 350
  }
}
```

### Log Events

- `cert_missing`: Certificate files not found
- `cert_parsed`: Certificate successfully parsed
- `cert_expired`: Certificate has expired
- `cert_expiring`: Certificate expiring soon (within `EXPIRY_WARN_DAYS`)
- `tls_probe_success`: TLS handshake succeeded
- `tls_probe_failure`: TLS handshake failed
- `mosquitto_restart_triggered`: Restart initiated
- `restart_completed`: Restart finished
- `restart_suppressed_cooldown`: Restart suppressed due to cooldown
- `restart_deferred`: Restart deferred (stability window)

## Behavior

### Certificate Rotation

When certificates are rotated:

1. Watcher detects file changes via `fsnotify` or polling
2. Waits for `STABILITY_WINDOW` to ensure writes are complete
3. Calculates new certificate hash
4. Compares with last known hash
5. If changed and cooldown elapsed, triggers restart
6. Updates internal state (hash, restart time)

### Expired Certificates

- Expired certificates are logged as errors
- **No restart is triggered** for expired certificates
- TLS probes will fail (logged separately)

### TLS Probe Failures

- TLS probe failures are logged but **do not prevent restarts**
- Failures may indicate:
  - Network connectivity issues
  - Certificate rejection by upstream
  - Upstream service unavailable
  - Configuration errors (SNI, address)

### Restart Debouncing

Restarts are prevented when:

- Files are still being written (within `STABILITY_WINDOW`)
- Cooldown period hasn't elapsed since last restart
- Certificate hash hasn't changed
- Restarts are disabled (`ENABLE_RESTART=false`)

## Acceptance Criteria

✅ Mosquitto runs normally with no certs  
✅ Certs appear → single restart occurs  
✅ Cert rotation → single restart occurs  
✅ Expired cert → no restart, clear error  
✅ TLS auth failure → diagnostic log, no restart  
✅ No restart loops under any failure mode  
✅ Runs fully non-root  

## Troubleshooting

### Container Won't Start

- Check Docker socket permissions
- Verify user is in docker group
- Check certificate directory is mounted

### Restarts Not Triggering

- Verify `ENABLE_RESTART=true`
- Check cooldown period hasn't elapsed
- Ensure certificate files are actually changing
- Check logs for `restart_suppressed_cooldown` or `restart_deferred`

### TLS Probe Failures

- Verify `UPSTREAM_ADDR` is correct
- Check network connectivity
- Verify `TLS_SNI` matches upstream server
- Check certificate is accepted by upstream
- Review certificate expiry

### Certificate Not Detected

- Verify files exist: `ca.crt`, `client.crt`, `client.key`
- Check files are non-empty
- Verify `CERT_DIR` path is correct
- Check mount permissions (read-only is fine)

## License

[Specify your license here]

## Contributing

[Contributing guidelines if applicable]
