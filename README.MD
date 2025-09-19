# AutoDast

**AutoDast** is a lightweight yet powerful web application security monitoring tool that automates vulnerability scanning using OWASP ZAP. It provides continuous security monitoring with scheduled scans, comprehensive reporting, and Google Chat integration for real-time notifications.

## Features

🔍 **Automated Security Scanning**
- Integration with OWASP ZAP for comprehensive security testing
- Optimized scan policies for different scenarios (quick, default, comprehensive)
- Spider and active scanning with configurable parameters

📊 **Comprehensive Reporting**
- HTML reports with detailed vulnerability information
- JSON reports for integration with other tools
- Risk-based categorization (High, Medium, Low, Informational)

⏰ **Scheduled Monitoring**
- Configurable scan intervals for continuous monitoring
- Non-blocking manual scans that don't interfere with scheduled scans
- Target-specific scheduling and policies

💬 **Google Chat Integration**
- Real-time notifications with scan results
- Rich card format with vulnerability breakdown
- Error notifications and status updates

📁 **File-Based Storage**
- No database dependencies - uses YAML and JSON files
- Scan history tracking and statistics
- Target status monitoring and trend analysis

🌐 **Web API Interface**
- RESTful API for external integrations
- Web dashboard for monitoring and management
- Manual scan triggering and status checking

## Quick Start

### Prerequisites

1. **Docker** (recommended): For using ZAP Docker containers
   - Install Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)
   - OR **OWASP ZAP**: Download and install from [zaproxy.org](https://www.zaproxy.org/) for manual installation
2. **Python 3.8+**: Required for running AutoDast

### Installation

1. Clone or download AutoDast:
```bash
cd autodast
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Choose your ZAP deployment method:

**Option A: Docker (Recommended)**
```bash
# AutoDast will automatically manage ZAP Docker containers
# No manual ZAP installation required
```

**Option B: Manual ZAP Installation**
```bash
# Start ZAP in daemon mode (headless)
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=* -config api.addrs.addr.regex=true

# Or start ZAP GUI
zap.sh
```

### Configuration

Edit `config.yaml` to configure your settings:

**Docker Mode (Recommended):**
```yaml
zap:
  host: "localhost"
  port: 8080
  api_key: ""

zap_docker:
  enabled: true  # Enable Docker mode
  image: "zaproxy/zap-stable"  # or "zaproxy/zap-weekly" for latest features
  container_name: "autodast-zap"
  port: 8080
  host_port: 8080
  api_key: ""
  memory_limit: "2g"
  auto_remove: true
  reports_volume: "./reports"
  session_volume: "./zap-session"

scheduler:
  interval_hours: 24  # Scan every 24 hours

google_chat:
  webhook_url: "YOUR_GOOGLE_CHAT_WEBHOOK_URL"  # Optional

targets:
  - name: "my-web-app"
    url: "https://myapp.example.com"
    scan_policy: "default"

  - name: "api-service"
    url: "https://api.example.com"
    scan_policy: "quick"
```

**Traditional Mode:**
```yaml
zap:
  host: "localhost"
  port: 8080
  api_key: ""  # Set if ZAP API key is required

zap_docker:
  enabled: false  # Disable Docker mode

# ... rest of configuration same as above
```

## Usage

### Command Line Interface

**Basic Commands:**
```bash
# Run in daemon mode (continuous monitoring)
python main.py daemon

# Run with web API interface
python main.py api

# Run manual scan for specific target
python main.py scan my-web-app

# Run manual scan with specific policy
python main.py scan my-web-app --policy comprehensive

# Check system status
python main.py status

# Test Google Chat webhook
python main.py test-webhook
```

**Docker Management Commands:**
```bash
# Start ZAP Docker container
python main.py start-zap

# Stop ZAP Docker container
python main.py stop-zap

# Restart ZAP Docker container
python main.py restart-zap

# View ZAP container logs
python main.py zap-logs
```

### Web Dashboard

Access the web dashboard at `http://localhost:8000` when running in API mode:

- **System Status**: Monitor AutoDast and ZAP status
- **Manual Scans**: Trigger scans on-demand
- **API Documentation**: Interactive API docs at `/docs`

### API Endpoints

- `GET /status` - Get system and target status
- `POST /scan` - Execute manual scan
- `GET /history` - Get scan history
- `GET /reports` - List available reports
- `GET /reports/{filename}` - Download specific report
- `POST /targets` - Add new monitoring target
- `DELETE /targets/{name}` - Remove target from monitoring

## Docker vs Traditional Deployment

### Docker Mode Benefits (Recommended)

✅ **Simplified Setup**: No need to manually install and configure OWASP ZAP
✅ **Consistent Environment**: Same ZAP version across all deployments
✅ **Automatic Management**: AutoDast handles container lifecycle
✅ **Isolation**: ZAP runs in isolated container environment
✅ **Resource Control**: Memory and CPU limits configurable
✅ **Easy Updates**: Simply change Docker image tag to update ZAP
✅ **Volume Persistence**: Reports and sessions saved to host filesystem

### Traditional Mode

Use traditional mode when:
- Docker is not available in your environment
- You need to use a custom ZAP installation
- You prefer manual ZAP management
- You have existing ZAP configurations to maintain

## Scan Policies

AutoDast includes three optimized scan policies:

### Default Policy
- Balanced approach for regular monitoring
- Spider: 5 children, depth 5, 10 minutes duration
- Active scan: 2 threads per host

### Quick Policy
- Fast scans for frequent monitoring
- Spider: 3 children, depth 3, 5 minutes duration
- Active scan: 1 thread per host

### Comprehensive Policy
- Thorough scans for detailed analysis
- Spider: 10 children, depth 10, 30 minutes duration
- Active scan: 4 threads per host

## Google Chat Integration

### Setup

1. Create a Google Chat webhook in your space
2. Add the webhook URL to your `config.yaml`
3. Test the integration: `python main.py test-webhook`

### Notification Types

- **Scan Results**: Vulnerability summary with risk breakdown
- **Error Notifications**: Scan failures and system errors
- **Status Updates**: System startup and configuration changes

## File Structure

```
autodast/
├── config.yaml           # Main configuration
├── requirements.txt      # Python dependencies
├── main.py              # CLI entry point
├── src/
│   ├── autodast.py      # Main AutoDast class
│   ├── api.py           # Web API interface
│   ├── config.py        # Configuration management
│   ├── zap_client.py    # OWASP ZAP integration
│   ├── scheduler.py     # Scan scheduling
│   ├── storage.py       # File-based storage
│   ├── report_generator.py # Report generation
│   └── google_chat.py   # Google Chat notifications
├── templates/
│   └── report.html      # HTML report template
├── data/                # Scan data and target status
│   ├── scans/          # Individual scan results
│   └── targets/        # Target status files
└── reports/            # Generated reports (HTML/JSON)
```

## Data Storage

AutoDast uses file-based storage for simplicity and portability:

- **Scan Results**: Stored as JSON files in `data/scans/`
- **Target Status**: Stored as YAML files in `data/targets/`
- **Reports**: Generated in `reports/` directory
- **Configuration**: Single `config.yaml` file

## Security Considerations

- **ZAP API Access**: Configure ZAP API key if required
- **Network Security**: Ensure ZAP is properly secured
- **Webhook URLs**: Keep Google Chat webhook URLs confidential
- **Report Access**: Secure the reports directory appropriately

## Troubleshooting

### Common Issues

**ZAP Connection Failed (Docker Mode)**
```bash
# Check Docker status
docker ps | grep autodast-zap

# Start ZAP container
python main.py start-zap

# Check container logs
python main.py zap-logs

# Restart container if needed
python main.py restart-zap
```

**ZAP Connection Failed (Traditional Mode)**
```bash
# Check if ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Start ZAP in daemon mode
zap.sh -daemon -host 0.0.0.0 -port 8080
```

**Docker Issues**
```bash
# Check if Docker is running
docker version

# Check Docker permissions (Linux/Mac)
sudo usermod -aG docker $USER

# Restart Docker service
sudo systemctl restart docker  # Linux
# or restart Docker Desktop
```

**Permission Issues**
```bash
# Ensure directories are writable
chmod 755 data reports
```

**Import Errors**
```bash
# Install missing dependencies
pip install -r requirements.txt
```

### Logs

AutoDast provides detailed logging. Check console output for:
- ZAP connection status
- Scan progress and results
- Error messages and stack traces
- Webhook delivery status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is released under the MIT License. See LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs for error details
3. Create an issue with relevant details

---

**AutoDast** - Simple, powerful, effective web application security monitoring.