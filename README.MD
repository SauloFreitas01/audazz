# DAST Continuous Monitoring System

A comprehensive Dynamic Application Security Testing (DAST) monitoring platform designed for continuous security assessment of web applications and their subdomains. This system transforms the original CLI-based ZAP automation tool into an enterprise-grade monitoring solution with advanced features like subdomain discovery, Grafana dashboards, and SIEM integration.

## 🚀 Features

### Core Capabilities
- **Continuous DAST Scanning** - Automated security scans based on configurable schedules
- **Multi-Target Management** - Monitor multiple domains and their subdomains simultaneously  
- **Advanced Subdomain Discovery** - Automated discovery using multiple tools (subfinder, assetfinder, amass)
- **Flexible Scheduling** - Priority-based scanning with cron-like scheduling
- **Comprehensive Reporting** - Multiple output formats (JSON, HTML, XML, SARIF)

### Integration & Monitoring
- **Grafana Dashboards** - Rich visualization and alerting capabilities
- **SIEM/SOAR Integration** - Support for Splunk, Elasticsearch, Azure Sentinel, IBM QRadar
- **Prometheus Metrics** - Detailed metrics collection and monitoring
- **CI/CD Integration** - Quality gates and pipeline integration
- **Real-time Notifications** - Slack, email, and webhook notifications

### Enterprise Features
- **High Availability** - Docker Compose with PostgreSQL and Redis
- **API Access** - RESTful API with authentication and role-based access
- **Scalable Architecture** - Containerized with horizontal scaling support
- **Data Retention** - Configurable report and data retention policies
- **Security Controls** - API authentication, network restrictions, audit logging

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   API Gateway   │    │  DAST Monitor   │
│    (Grafana)    │    │    (Nginx)      │    │   (Python)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ├───────────────────────┼───────────────────────┤
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Prometheus    │    │   PostgreSQL    │    │     Redis       │
│   (Metrics)     │    │   (Storage)     │    │   (Queuing)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                                            │
         │              ┌─────────────────┐           │
         └──────────────│  OWASP ZAP      │───────────┘
                        │  (Scanning)     │
                        └─────────────────┘
```

## 🛠️ Installation

### Prerequisites
- Docker and Docker Compose
- 4GB+ RAM recommended
- 50GB+ disk space for reports
- Network access for subdomain discovery tools

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd audazz
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

3. **Start the monitoring system**
   ```bash
   docker-compose up -d
   ```

4. **Access the dashboard**
   - Grafana: http://localhost:3000 (admin/admin-change-me)
   - API: http://localhost:8080
   - Metrics: http://localhost:9090

### Environment Configuration

Create a `.env` file with the following variables:

```bash
# Database
POSTGRES_PASSWORD=secure-password-change-me
REDIS_PASSWORD=redis-password-change-me

# Grafana
GRAFANA_ADMIN_PASSWORD=admin-change-me
GRAFANA_API_KEY=your-api-key

# SIEM Integration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SIEM_WEBHOOK_URL=https://your-siem-webhook

# API Authentication
ADMIN_API_TOKEN=admin-token-change-me
READONLY_API_TOKEN=readonly-token-change-me

# Optional: InfluxDB (if using instead of Prometheus)
INFLUXDB_ADMIN_PASSWORD=influx-admin-password
INFLUXDB_ADMIN_TOKEN=influx-token-change-me
```

## ⚙️ Configuration

### Main Configuration (dast_config.yaml)

```yaml
# Scan scheduling based on priority
scan_schedules:
  high_priority: "0 */2 * * *"    # Every 2 hours
  medium_priority: "0 */6 * * *"  # Every 6 hours  
  low_priority: "0 0 */1 * *"     # Daily

# Grafana integration
grafana:
  enabled: true
  url: "http://localhost:3000"
  api_key: "${GRAFANA_API_KEY}"

# SIEM integration
siem:
  enabled: true
  type: "webhook"  # webhook, splunk, elasticsearch, sentinel, qradar
  webhook_url: "${SIEM_WEBHOOK_URL}"
  severity_threshold: "medium"
```

### Adding Scan Targets

Using the Python API:
```python
python dast_monitor.py --add-target example.com --scan-type standard --priority 3
```

Using the REST API:
```bash
curl -X POST "http://localhost:8080/api/v1/targets" \
  -H "Authorization: Bearer ${ADMIN_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scan_type": "standard", 
    "priority": 3
  }'
```

## 🔍 Scanning Types

### Standard Web Application Scan
- **Purpose**: General web application security testing
- **Features**: Spider crawling, passive + active scanning
- **Duration**: 30-60 minutes typical
- **Use Case**: Traditional web applications

### Single Page Application (SPA) Scan  
- **Purpose**: Modern JavaScript applications
- **Features**: AJAX spider, Selenium browser automation
- **Duration**: 45-90 minutes typical
- **Use Case**: React, Angular, Vue.js applications

### API Service Scan
- **Purpose**: RESTful API and web service testing
- **Features**: OpenAPI spec import, API-specific tests
- **Duration**: 15-45 minutes typical
- **Use Case**: REST APIs, GraphQL endpoints

## 📊 Monitoring & Dashboards

### Grafana Dashboards

The system includes pre-built Grafana dashboards:

1. **Security Overview**
   - Total scans and targets
   - Alert severity distribution
   - Scan success rates
   - Recent findings

2. **Vulnerability Trends** 
   - Historical vulnerability data
   - Risk trend analysis
   - Target comparison metrics
   - Remediation tracking

3. **System Health**
   - Scan duration monitoring
   - Error rates and failures
   - Resource utilization
   - Queue status

### Prometheus Metrics

Key metrics exposed:
- `dast_scan_duration_seconds` - Scan execution time
- `dast_alerts_by_severity` - Alert counts by risk level
- `dast_scans_total` - Total scan counter
- `dast_targets_total` - Monitored targets count
- `dast_subdomains_discovered` - Subdomain discovery metrics

## 🔗 Integrations

### SIEM/SOAR Platforms

Supported integrations:
- **Splunk** - HEC endpoint integration
- **Elasticsearch** - Direct indexing with Kibana dashboards  
- **Azure Sentinel** - Log Analytics workspace integration
- **IBM QRadar** - API-based event forwarding
- **Generic Webhook** - Custom SIEM integration

### CI/CD Pipelines

Quality gate integration:
```yaml
# Jenkins Pipeline Example
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def response = httpRequest(
                        url: "${DAST_MONITOR_URL}/api/v1/scan",
                        httpMode: 'POST',
                        authentication: 'dast-api-token',
                        requestBody: '{"target": "${APP_URL}", "wait": true}'
                    )
                    
                    def result = readJSON text: response.content
                    if (result.alerts_high > 0) {
                        error("High severity vulnerabilities found")
                    }
                }
            }
        }
    }
}
```

### Notification Channels

Supported notification methods:
- **Slack** - Rich message formatting with alert details
- **Email** - SMTP integration with HTML reports
- **Microsoft Teams** - Webhook-based notifications  
- **Custom Webhooks** - Flexible integration options

## 🚦 API Reference

### Authentication

All API requests require authentication:
```bash
curl -H "Authorization: Bearer ${API_TOKEN}" \
  "http://localhost:8080/api/v1/status"
```

### Key Endpoints

| Endpoint | Method | Description |
|----------|---------|-------------|
| `/api/v1/targets` | GET | List all targets |
| `/api/v1/targets` | POST | Add new target |
| `/api/v1/scan` | POST | Trigger scan |
| `/api/v1/results/{target}` | GET | Get scan results |
| `/api/v1/status` | GET | System status |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |

### Example API Usage

**Add a target:**
```bash
curl -X POST "http://localhost:8080/api/v1/targets" \
  -H "Authorization: Bearer ${ADMIN_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scan_type": "standard",
    "priority": 2,
    "auth_config": {
      "type": "form",
      "login_url": "https://example.com/login",
      "username": "testuser",
      "password": "testpass"
    }
  }'
```

**Get scan results:**
```bash
curl -H "Authorization: Bearer ${READONLY_API_TOKEN}" \
  "http://localhost:8080/api/v1/results/example.com?limit=10"
```

## 🐳 Docker Deployment

### Production Deployment

1. **Configure production environment**
   ```bash
   # Use production compose file
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

2. **Enable SSL/TLS**
   ```bash
   # Copy SSL certificates to nginx/ssl/
   # Update nginx configuration for HTTPS
   ```

3. **Scale services**
   ```bash
   docker-compose up -d --scale dast-monitor=3
   ```

### Service Profiles

Different deployment profiles available:
- **Default**: Core monitoring services
- **Production**: With nginx reverse proxy and SSL
- **InfluxDB**: Use InfluxDB instead of Prometheus  
- **Elastic**: Include Elasticsearch and Kibana
- **Discovery**: Enhanced subdomain discovery services

## 🔧 Troubleshooting

### Common Issues

**Scans failing with permission errors:**
```bash
# Ensure Docker socket permissions
sudo usermod -aG docker $USER
# Or run with elevated privileges
```

**High memory usage:**
```yaml
# Limit ZAP memory in dast_config.yaml
zap:
  memory: "2g"
  timeout: 1800
```

**Subdomain discovery not working:**
```bash
# Install discovery tools
sudo apt install subfinder assetfinder
# Or use Docker-based tools
```

### Log Analysis

```bash
# Monitor main application logs
docker-compose logs -f dast-monitor

# Check scan execution logs  
docker-compose logs dast-monitor | grep "scan_id"

# Database connection issues
docker-compose logs postgres
```

### Performance Tuning

**Concurrent scans:**
```yaml
max_concurrent_scans: 5  # Adjust based on resources
```

**Scan optimization:**
```yaml
performance:
  scan_optimization:
    max_crawl_depth: 3     # Reduce for faster scans
    request_delay: 50      # Increase for rate limiting
```

## 🔒 Security Considerations

### Network Security
- Use firewalls to restrict access to monitoring ports
- Enable TLS for all external communications
- Consider VPN access for management interfaces

### Data Protection  
- Encrypt sensitive configuration data
- Regular backup of scan results and configurations
- Implement data retention policies

### Access Control
- Use strong API tokens and rotate regularly
- Implement role-based access control
- Monitor API usage and authentication failures

## 🚀 Getting Started

1. **Set up your targets**
   ```bash
   python dast_monitor.py --add-target yourapp.com --scan-type standard --priority 3
   ```

2. **Monitor the dashboard**
   - Open Grafana at http://localhost:3000
   - View the "DAST Security Monitoring" dashboard
   - Set up alerts for high-severity findings

3. **Configure integrations**
   - Set up SIEM forwarding in `dast_config.yaml`
   - Configure Slack notifications
   - Enable CI/CD quality gates

## 📞 Support

For questions, issues, or contributions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the configuration examples

---

**Transform your security scanning from reactive to proactive with continuous DAST monitoring!** 🛡️