# 🚀 Beginner's Guide to DAST Continuous Monitoring System

Welcome! This guide will help you get started with the DAST (Dynamic Application Security Testing) Continuous Monitoring System from scratch. No prior experience with security scanning required!

## 📋 What This Tool Does

This tool automatically scans your websites and web applications for security vulnerabilities on a continuous basis. Think of it as a security guard that:
- Monitors your websites 24/7
- Finds security problems before hackers do
- Creates beautiful dashboards to visualize security status
- Sends alerts when issues are found
- Integrates with your existing tools

## 🎯 Prerequisites (What You Need First)

### System Requirements
- **Computer**: Windows, Mac, or Linux
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 50GB free space
- **Internet**: Stable internet connection

### Software Requirements
1. **Docker Desktop** (we'll install this together)
2. **Git** (for downloading the tool)

## 📥 Step 1: Install Docker Desktop

Docker helps run the tool in containers, making installation much easier.

### Windows/Mac:
1. Go to [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
2. Download Docker Desktop for your OS
3. Run the installer and follow instructions
4. Restart your computer when prompted
5. Open Docker Desktop and wait for it to start

### Linux (Ubuntu/Debian):
```bash
# Update your system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose-plugin

# Restart to apply changes
sudo reboot
```

### Verify Installation:
```bash
docker --version
docker-compose --version
```

## 📥 Step 2: Download the Tool

### Option 1: Using Git (Recommended)
```bash
# Open terminal/command prompt
git clone <repository-url>
cd audazz
```

### Option 2: Download ZIP
1. Click "Download ZIP" on the repository page
2. Extract to a folder (e.g., `C:\audazz` or `~/audazz`)
3. Open terminal in that folder

## ⚙️ Step 3: Basic Configuration

### Create Your Environment File
```bash
# Copy the example configuration
cp .env.example .env

# For Windows Command Prompt:
copy .env.example .env
```

### Edit Configuration (Important!)
Open `.env` file in a text editor and change these passwords:

```bash
# Change these default passwords for security!
POSTGRES_PASSWORD=your-secure-database-password-here
REDIS_PASSWORD=your-secure-redis-password-here
GRAFANA_ADMIN_PASSWORD=your-grafana-password-here

# API tokens (generate random strings)
ADMIN_API_TOKEN=admin-token-your-random-string-here
READONLY_API_TOKEN=readonly-token-your-random-string-here

# Optional: Add Slack webhook for notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

**💡 Tip**: Use a password generator to create secure passwords!

## 🚀 Step 4: First-Time Setup

### Automated Setup (Recommended)
If you're on Linux/Mac:
```bash
chmod +x scripts/setup/install.sh
./scripts/setup/install.sh
```

### Manual Setup (All Platforms)
```bash
# Navigate to Docker deployment directory
cd deployment/docker

# Create required directories
mkdir -p ../../data/{reports,logs,exports}
mkdir -p ../../security/certificates

# Pull all required images (this may take 10-15 minutes)
docker-compose pull

# Start the database services first
docker-compose up -d postgres redis

# Wait 30 seconds for databases to initialize
# Windows: timeout 30
# Linux/Mac: sleep 30

# Start monitoring services
docker-compose up -d grafana prometheus

# Finally, start the main application
docker-compose up -d dast-monitor
```

## 🎯 Step 5: Verify Installation

### Check if Services are Running
```bash
docker-compose ps
```

You should see all services as "Up" or "healthy".

### Access Your Dashboards

1. **Grafana Dashboard**: [http://localhost:3000](http://localhost:3000)
   - Username: `admin`
   - Password: (what you set in `.env`)

2. **API Endpoint**: [http://localhost:8080](http://localhost:8080)

3. **Prometheus Metrics**: [http://localhost:9091](http://localhost:9091)

## 🎯 Step 6: Add Your First Target

Now let's scan your first website!

### Using Python Script:
```bash
python main.py --add-target example.com --scan-type standard --priority 3
```

### Using API (Advanced):
```bash
curl -X POST "http://localhost:8080/api/v1/targets" \
  -H "Authorization: Bearer your-admin-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scan_type": "standard",
    "priority": 3
  }'
```

## 🔍 Step 7: Run Your First Scan

### Start a Manual Scan:
```bash
python main.py --scan example.com
```

### Monitor Progress:
- Watch logs: `docker-compose logs -f dast-monitor`
- Check Grafana dashboard for real-time updates
- Reports will be saved in `data/reports/`

## 📊 Step 8: Understanding Your Results

### Grafana Dashboard
1. Open [http://localhost:3000](http://localhost:3000)
2. Look for "DAST Security Monitoring" dashboard
3. You'll see:
   - **Total scans**: How many scans completed
   - **Vulnerabilities found**: Count by severity
   - **Recent alerts**: Latest security issues
   - **Scan trends**: Performance over time

### Vulnerability Severity Levels:
- 🔴 **High**: Critical issues requiring immediate attention
- 🟡 **Medium**: Important security concerns
- 🟢 **Low**: Minor issues or informational findings
- ℹ️ **Info**: General information about your site

### Report Files
Check the `data/reports/` folder for detailed reports in multiple formats:
- **HTML**: Human-readable reports
- **JSON**: Machine-readable data
- **XML**: For integration with other tools

## 🔧 Common Issues and Solutions

### "Container won't start"
```bash
# Check logs for errors
docker-compose logs dast-monitor

# Restart services
docker-compose down
docker-compose up -d
```

### "Out of disk space"
```bash
# Clean up old Docker images
docker system prune -f

# Remove old reports (keep last 30 days)
find data/reports/ -name "*.html" -mtime +30 -delete
```

### "Can't access Grafana"
1. Ensure Docker is running
2. Check if port 3000 is blocked by firewall
3. Try accessing via IP: `http://127.0.0.1:3000`

### "Scans failing"
1. Check if target website is accessible
2. Verify your internet connection
3. Look at logs: `docker-compose logs dast-monitor`

## 📅 Setting Up Automated Scans

### Edit Configuration:
Open `config/dast_config.yaml` and set scan schedules:

```yaml
scan_schedules:
  high_priority: "0 */2 * * *"    # Every 2 hours
  medium_priority: "0 */6 * * *"  # Every 6 hours  
  low_priority: "0 0 */1 * *"     # Daily
```

### Schedule Format (Cron):
- `0 */2 * * *`: Every 2 hours
- `0 9 * * 1-5`: Weekdays at 9 AM
- `0 0 * * 0`: Sundays at midnight

## 🔔 Setting Up Notifications

### Slack Notifications:
1. Create a Slack app and webhook URL
2. Add to your `.env` file:
   ```bash
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```
3. Restart services: `docker-compose restart`

### Email Notifications:
Configure in `config/dast_config.yaml`:
```yaml
notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    recipients: ["security-team@company.com"]
```

## 🛡️ Security Best Practices

### 1. Change Default Passwords
- Never use default passwords in production
- Use strong, unique passwords for each service

### 2. Secure API Access
- Keep API tokens secret
- Use read-only tokens when possible
- Rotate tokens regularly

### 3. Network Security
- Use firewall to restrict access
- Consider VPN for remote access
- Enable HTTPS in production

### 4. Regular Maintenance
```bash
# Weekly maintenance script
docker-compose restart    # Restart services
docker system prune -f    # Clean up unused images
```

## 📚 Next Steps

### Beginner Level:
1. ✅ Complete this setup guide
2. Add 2-3 websites to monitor
3. Set up Slack notifications
4. Schedule weekly scans

### Intermediate Level:
1. Configure custom scan profiles
2. Integrate with CI/CD pipelines
3. Set up email alerts
4. Create custom Grafana dashboards

### Advanced Level:
1. Deploy with SSL/HTTPS
2. Set up high availability
3. Integrate with SIEM systems
4. Develop custom plugins

## 🆘 Getting Help

### Documentation:
- `README.md`: Detailed technical documentation
- `ARCHITECTURE.md`: System architecture details
- `config/`: Example configurations

### Troubleshooting:
1. Check Docker logs: `docker-compose logs`
2. Verify all services are running: `docker-compose ps`
3. Test connectivity: `curl http://localhost:8080/health`

### Community Support:
- Create an issue in the repository
- Check existing issues for solutions
- Review troubleshooting section in README.md

## 🎉 Congratulations!

You now have a fully functional security monitoring system! This tool will help you:

- **Detect vulnerabilities** before they become incidents
- **Monitor security trends** over time
- **Automate security testing** in your workflow
- **Generate professional reports** for compliance

Remember: Security is an ongoing process. Regular monitoring and timely remediation of issues are key to maintaining a secure environment.

---

## 📋 Quick Commands Reference

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# View logs
docker-compose logs -f dast-monitor

# Restart specific service
docker-compose restart dast-monitor

# Add new target
python main.py --add-target example.com --priority 3

# Run manual scan
python main.py --scan example.com

# Check system status
curl http://localhost:8080/health
```

Happy scanning! 🛡️✨