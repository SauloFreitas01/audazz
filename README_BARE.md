# DAST Monitor - Bare Version

A minimal version of the DAST (Dynamic Application Security Testing) monitoring system without Grafana, Prometheus, Redis dependencies. This version focuses on core scanning functionality and Google Workspace notifications.

## Features

- **OWASP ZAP Integration**: Automated security scanning using ZAP
- **Google Workspace Notifications**: Rich card-based notifications to Google Chat
- **File-based Storage**: No database dependencies - uses local file storage
- **Multi-domain Support**: Scan multiple domains and subdomains
- **Report Generation**: JSON, HTML, XML, and SARIF format reports
- **CI/CD Integration**: JUnit XML output and quality gates
- **Subdomain Discovery**: Automated subdomain enumeration
- **Metrics Processing**: Security scoring and vulnerability tracking

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Google Workspace webhook URL (optional but recommended)

### 1. Setup Environment

```bash
# Clone the repository and switch to bare branch
git clone <repository-url>
cd audazz
git checkout bare

# Set environment variables
export GOOGLE_WORKSPACE_WEBHOOK_URL="https://chat.googleapis.com/v1/spaces/.../messages?key=..."
export POSTGRES_PASSWORD="your-secure-password"
export ADMIN_API_TOKEN="your-admin-token"
```

### 2. Start Services

```bash
# Make startup script executable
chmod +x scripts/start_bare.sh

# Start the bare version
./scripts/start_bare.sh
```

### 3. Run Your First Scan

```bash
# Process existing reports
python scripts/maintenance/process_zap_metrics.py --summary

# Process specific domain
python scripts/maintenance/process_zap_metrics.py --domain example.com --summary

# Send to Google Workspace
python scripts/maintenance/process_zap_metrics.py \
    --domain example.com \
    --google-workspace-webhook "$GOOGLE_WORKSPACE_WEBHOOK_URL" \
    --summary
```

## Configuration

### Main Configuration File

The bare version uses `deployment/docker/dast_config_bare.yaml` with simplified settings:

```yaml
# Google Workspace integration (primary notification method)
google_workspace:
  enabled: true
  webhook_url: "${GOOGLE_WORKSPACE_WEBHOOK_URL}"
  message_style: "card"  # or "simple"
  severity_threshold: "medium"

# File-based storage (no database required)
storage:
  type: "file"
  data_directory: "data"
  reports_directory: "reports"

# Simplified metrics
metrics:
  enabled: true
  output_format: "json"
  output_file: "data/metrics.json"
```

### Docker Compose

Uses `deployment/docker/docker-compose.bare.yml` with minimal services:

- **dast-monitor**: Main application
- **postgres**: Database (simplified, can be removed for fully file-based)
- **subdomain-discovery**: Optional subdomain enumeration
- **cleanup**: Automated cleanup service

## Google Workspace Integration

### Setup Webhook

1. Go to Google Chat
2. Navigate to the space where you want notifications
3. Click on the space name → "Manage webhooks"
4. Create a new webhook and copy the URL

### Message Formats

**Card Format** (Rich notifications):
- Security score visualization
- Vulnerability breakdown by risk level
- Top vulnerabilities list
- Action recommendations
- Quick action buttons

**Simple Format** (Text-based):
- Plain text summary
- Basic vulnerability counts
- Suitable for basic spaces

### Example Usage

```bash
# Rich card notifications
python scripts/maintenance/process_zap_metrics.py \
    --google-workspace-webhook "$WEBHOOK_URL" \
    --google-workspace-style card \
    --domain brokencrystals.com

# Simple text notifications
python scripts/maintenance/process_zap_metrics.py \
    --google-workspace-webhook "$WEBHOOK_URL" \
    --google-workspace-style simple \
    --summary
```

## Command Line Usage

### List Available Domains

```bash
python scripts/maintenance/process_zap_metrics.py --list-domains
```

### Process Specific Domain

```bash
python scripts/maintenance/process_zap_metrics.py --domain example.com --summary
```

### Process All Domains

```bash
python scripts/maintenance/process_zap_metrics.py --all-domains --summary
```

### Generate Reports

```bash
# JUnit XML for CI/CD
python scripts/maintenance/process_zap_metrics.py \
    --domain example.com \
    --output-junit results.xml \
    --check-gates

# Grafana JSON metrics
python scripts/maintenance/process_zap_metrics.py \
    --output-grafana metrics.json
```

### Quality Gates

```bash
# Set thresholds and check
MIN_SECURITY_SCORE=80 \
MAX_MEDIUM_RISK=5 \
MAX_TOTAL_ALERTS=20 \
python scripts/maintenance/process_zap_metrics.py --check-gates
```

## Architecture

### Removed Components

The bare version removes these components from the full version:

- **Grafana**: Dashboard and visualization
- **Prometheus**: Time-series metrics collection
- **Redis**: Caching and task queuing
- **InfluxDB**: Alternative time-series database
- **Elasticsearch/Kibana**: SIEM integration

### Simplified Workflow

1. **Scan Execution**: ZAP containers perform security scans
2. **Report Generation**: Results saved in organized directory structure
3. **Metrics Processing**: Python script processes reports and calculates scores
4. **Notifications**: Google Workspace cards sent with results
5. **File Storage**: All data stored in local files

### Directory Structure

```
reports/
├── domain.com/
│   ├── main_domain/
│   │   ├── json/
│   │   ├── html/
│   │   ├── xml/
│   │   └── sarif/
│   └── subdomains/
│       └── subdomain/
│           ├── json/
│           └── ...
data/
├── metrics.json
├── health.json
└── subdomains.json
logs/
└── dast_monitor.log
```

## Security Best Practices

### Authentication

- API tokens for authentication
- IP-based access control
- Rate limiting enabled

### Network Security

```yaml
security:
  network:
    allowed_ips: ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    rate_limiting:
      enabled: true
      requests_per_minute: 60
```

### Webhook Security

- Use HTTPS webhooks only
- Rotate webhook URLs regularly
- Monitor webhook usage

## Troubleshooting

### Common Issues

**Services won't start:**
```bash
# Check Docker status
docker info

# View service logs
docker-compose -f deployment/docker/docker-compose.bare.yml logs
```

**No notifications received:**
```bash
# Test webhook manually
curl -X POST "$GOOGLE_WORKSPACE_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"text": "Test message from DAST Monitor"}'
```

**Reports not found:**
```bash
# Check report directory structure
find reports -name "*.json" | head -10

# Verify file permissions
ls -la reports/
```

### Debug Mode

Enable debug logging in configuration:

```yaml
log_level: "DEBUG"
development:
  debug_mode: true
```

## Migration from Full Version

To migrate from the full version:

1. Export existing scan configurations
2. Backup report data
3. Switch to bare branch
4. Update configuration files
5. Restart with bare docker-compose

## Performance Optimization

### Resource Limits

```yaml
performance:
  resource_limits:
    max_memory_per_scan: "4g"
    max_cpu_per_scan: 2
    disk_space_threshold: "10GB"
```

### Scan Optimization

```yaml
performance:
  scan_optimization:
    skip_static_content: true
    max_crawl_depth: 5
    max_crawl_children: 100
    request_delay: 100
```

## Contributing

When contributing to the bare version:

1. Keep dependencies minimal
2. Focus on core scanning functionality
3. Maintain Google Workspace integration
4. Test with file-based storage
5. Document configuration changes

## License

Same license as the main project.