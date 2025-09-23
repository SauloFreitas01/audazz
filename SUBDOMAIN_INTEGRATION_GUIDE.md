# Subdomain Discovery Integration Guide

This guide explains how to integrate your AutoDast security scanner with subdomain discovery tools for automated, comprehensive security coverage.

## 🚀 Overview

The integration provides:

- **📁 File-based target management** - Read domains from `targets/domains.txt` and subdomains from `targets/subdomains/` directory
- **🔄 Monthly comprehensive scans** - Automated monthly security assessments of all discovered assets
- **⚡ Real-time new subdomain scanning** - Immediate security assessment when new subdomains are discovered
- **📊 Executive reporting** - Domain-grouped vulnerability analysis and trends
- **🔔 Intelligent alerting** - Different alert levels for scheduled vs. urgent new findings
- **🎯 Dynamic targeting** - Automatically includes newly discovered subdomains without manual configuration

## 🏗️ Architecture

### Workflow Components

1. **Integrated Monthly Security Scan** (`integrated-monthly-security-scan.yml`)
   - Scheduled monthly comprehensive scans
   - Reads targets from discovery integration
   - Generates executive reports with domain breakdown
   - Supports manual triggers with filtering options

2. **New Subdomain Security Scan** (`new-subdomain-scan.yml`)
   - Triggered by changes to target files
   - Rapid security assessment of new discoveries
   - Urgent alerting for critical findings
   - Auto-creates GitHub issues for critical vulnerabilities

3. **Target Manager** (`autoDAST/src/target_manager.py`)
   - Manages domain and subdomain sources
   - Detects changes and new targets
   - Organizes targets for parallel scanning
   - Tracks scanning history

## 📂 Directory Structure

```
targets/
├── domains.txt                     # Main domains list
└── subdomains/                     # Subdomain discovery results
    ├── example.com.txt             # Subdomains for example.com
    ├── mycompany.com.txt           # Subdomains for mycompany.com
    └── api.example.com/            # Alternative: subdomain directory
        └── subdomains.txt          # Subdomains file
```

## 🔧 Setup Instructions

### 1. Configure Target Files

#### Main Domains File (`targets/domains.txt`)
```
# Add your primary domains here, one per line
# Comments start with #

example.com
mycompany.com
api.service.com
```

#### Subdomain Files (`targets/subdomains/`)

**Option A: Single file per domain**
```
# targets/subdomains/example.com.txt
www.example.com
api.example.com
admin.example.com
staging.example.com
```

**Option B: Directory structure**
```
# targets/subdomains/example.com/subdomains.txt
www.example.com
api.example.com
admin.example.com
```

### 2. Integration with Subdomain Discovery Tools

#### For automated subdomain discovery tools that update files:

```bash
# Your subdomain discovery script
#!/bin/bash
DOMAIN="example.com"

# Run your subdomain discovery tool
subfinder -d $DOMAIN > temp_subdomains.txt
amass enum -d $DOMAIN >> temp_subdomains.txt

# Update the subdomains file
sort temp_subdomains.txt | uniq > targets/subdomains/${DOMAIN}.txt

# Commit changes (this will trigger security scan)
git add targets/subdomains/${DOMAIN}.txt
git commit -m "Update subdomains for ${DOMAIN}"
git push
```

#### For CI/CD integration:

```yaml
# In your subdomain discovery workflow
- name: Update subdomain files
  run: |
    # Your discovery logic here
    echo "New subdomains found" > targets/subdomains/newdomain.com.txt

- name: Commit subdomain updates
  run: |
    git config --local user.email "action@github.com"
    git config --local user.name "GitHub Action"
    git add targets/subdomains/
    git commit -m "Auto-update: New subdomains discovered"
    git push
```

### 3. Configure Secrets

Add to your GitHub repository secrets:

```
GOOGLE_WORKSPACE_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/YOUR_SPACE/messages?key=YOUR_KEY
```

### 4. Test the Integration

```bash
# Clone and navigate to your repository
cd your-repo

# Test target discovery
python autoDAST/src/target_manager.py --action summary

# Test matrix generation
python autoDAST/src/target_manager.py --action matrix

# Test new target detection
python autoDAST/src/target_manager.py --action detect-new
```

## 🎮 Usage Scenarios

### Monthly Comprehensive Scans

**Automatic (Scheduled):**
- Runs automatically on the 1st of each month
- Scans all configured domains and discovered subdomains
- Generates executive reports with trend analysis
- Creates GitHub releases with comprehensive documentation

**Manual Trigger Options:**
```yaml
# Scan all targets
scan_type: all

# Scan only new targets since last run
scan_type: new-only

# Scan specific domain and its subdomains
scan_type: specific-domain
specific_domain: example.com
```

### Real-time New Subdomain Scanning

**Triggered automatically when:**
- New domains added to `targets/domains.txt`
- New subdomains added to any file in `targets/subdomains/`
- Pull requests modify target files

**Response actions:**
- Immediate rapid security scan (quick policy)
- Urgent Google Workspace alerts for critical findings
- Auto-creation of GitHub issues for critical vulnerabilities
- Artifact storage for investigation

### Force Scanning

```bash
# Force scan all targets immediately
gh workflow run new-subdomain-scan.yml -f force_scan_all=true

# Comprehensive scan with specific policy
gh workflow run integrated-monthly-security-scan.yml -f scan_type=all -f scan_policy=comprehensive
```

## 📊 Reporting and Alerting

### Executive Reports

**Monthly reports include:**
- Domain-level risk breakdown
- Subdomain vulnerability distribution
- Trend analysis over time
- Executive summary with business impact
- Actionable recommendations

**Report formats:**
- JSON (machine-readable)
- HTML (executive presentation)
- Markdown (notifications)

### Alert Levels

**Scheduled Monthly Scans:**
- 📊 Executive summary style
- 📈 Trend analysis focus
- 🎯 Strategic recommendations

**New Subdomain Discoveries:**
- 🚨 Urgent priority alerts
- ⚡ Real-time notifications
- 🔍 Tactical response focus

### Google Workspace Integration

**Monthly scan alerts include:**
- Overall risk assessment
- Domain coverage statistics
- Vulnerability trends
- Strategic recommendations

**New subdomain alerts include:**
- Immediate threat assessment
- Critical finding highlights
- Urgent response actions
- Asset verification prompts

## 🔧 Customization Options

### Scan Policies

```yaml
# Quick scan for new discoveries
scan_policy: quick

# Comprehensive monthly assessments
scan_policy: comprehensive

# Baseline security checks
scan_policy: baseline
```

### Target Organization

**File naming patterns supported:**
- `domain.com.txt`
- `domain_subdomains.txt`
- `subdomains_domain.txt`
- `domain/subdomains.txt`

### Matrix Configuration

```python
# Adjust parallel processing
--max-per-job 20  # Default: 20 targets per job
--max-per-job 50  # For larger infrastructures
```

### Integration Timing

```yaml
# Modify monthly schedule
cron: '0 2 1 * *'     # 1st of month at 2 AM UTC
cron: '0 2 15 * *'    # 15th of month at 2 AM UTC
cron: '0 2 * * 1'     # Every Monday at 2 AM UTC
```

## 🛠️ Advanced Configuration

### Custom Target Discovery

```python
# Extend TargetManager for custom sources
class CustomTargetManager(TargetManager):
    def get_custom_targets(self):
        # Your custom logic here
        return custom_targets
```

### Integration with External Tools

**Subdomain discovery tools:**
- Subfinder
- Amass
- Findomain
- Assetfinder
- Custom discovery scripts

**Example integration script:**
```bash
#!/bin/bash
# continuous-discovery.sh

while true; do
    for domain in $(grep -v '^#' targets/domains.txt); do
        echo "Discovering subdomains for $domain"

        # Run discovery tools
        subfinder -d $domain -silent > temp_${domain}.txt
        amass enum -d $domain -silent >> temp_${domain}.txt

        # Process and update if changes found
        if ! cmp -s temp_${domain}.txt targets/subdomains/${domain}.txt; then
            mv temp_${domain}.txt targets/subdomains/${domain}.txt

            # Commit changes to trigger scan
            git add targets/subdomains/${domain}.txt
            git commit -m "Auto-discovery: Updated subdomains for ${domain}"
            git push
        fi
    done

    # Wait 6 hours before next discovery cycle
    sleep 21600
done
```

### Webhook Integration

**For external discovery tools:**
```python
# webhook-handler.py
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/subdomain-discovered', methods=['POST'])
def handle_new_subdomain():
    data = request.json
    domain = data['domain']
    subdomain = data['subdomain']

    # Update subdomain file
    with open(f'targets/subdomains/{domain}.txt', 'a') as f:
        f.write(f'{subdomain}\n')

    # Trigger git commit
    subprocess.run(['git', 'add', f'targets/subdomains/{domain}.txt'])
    subprocess.run(['git', 'commit', '-m', f'New subdomain: {subdomain}'])
    subprocess.run(['git', 'push'])

    return {'status': 'success'}
```

## 🔍 Monitoring and Troubleshooting

### Monitoring Integration Health

```bash
# Check target discovery status
python autoDAST/src/target_manager.py --action summary

# Validate target files
find targets -name "*.txt" -exec wc -l {} \;

# Check for recent changes
git log --oneline targets/
```

### Common Issues

**No targets detected:**
```bash
# Check domains.txt format
cat targets/domains.txt | grep -v '^#' | head

# Verify subdomain files exist
ls -la targets/subdomains/

# Test target manager
python autoDAST/src/target_manager.py --action list
```

**Scans not triggering:**
```bash
# Check workflow files
ls -la .github/workflows/

# Verify file paths in triggers
git diff HEAD~1 HEAD --name-only | grep targets
```

**Missing subdomain data:**
```bash
# Check file naming conventions
find targets/subdomains -name "*.txt" -type f

# Verify file contents
head targets/subdomains/*.txt
```

### Performance Optimization

**For large subdomain sets:**
- Increase `max-per-job` parameter
- Use faster scan policies for new discoveries
- Implement subdomain prioritization
- Configure timeout adjustments

**For frequent discoveries:**
- Implement discovery batching
- Add change detection delays
- Use incremental scanning strategies

## 🚀 Migration from Manual Targets

### Step 1: Export Current Targets

```python
# export-current-targets.py
import json

# Your current target configuration
current_targets = {
    "example.com": ["www.example.com", "api.example.com"],
    "mycompany.com": ["admin.mycompany.com", "staging.mycompany.com"]
}

# Create domains.txt
with open('targets/domains.txt', 'w') as f:
    f.write("# Migrated from manual configuration\n")
    for domain in current_targets.keys():
        f.write(f"{domain}\n")

# Create subdomain files
for domain, subdomains in current_targets.items():
    with open(f'targets/subdomains/{domain}.txt', 'w') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
```

### Step 2: Update Workflow Configuration

```yaml
# Replace static matrix with dynamic discovery
# OLD:
matrix:
  target: ["example.com", "api.example.com"]

# NEW:
matrix: ${{ fromJson(needs.discover-targets.outputs.matrix) }}
```

### Step 3: Test Integration

```bash
# Test target discovery
python autoDAST/src/target_manager.py --action matrix

# Verify workflow configuration
gh workflow run integrated-monthly-security-scan.yml -f scan_type=all
```

## 📈 Best Practices

### Target Management

1. **Organize by business criticality**
   ```
   targets/domains.txt:
   # Critical production domains
   api.company.com
   app.company.com

   # Development/staging domains
   staging.company.com
   dev.company.com
   ```

2. **Use consistent naming**
   ```
   targets/subdomains/
   ├── production.domain.com.txt
   ├── staging.domain.com.txt
   └── development.domain.com.txt
   ```

3. **Implement validation**
   ```bash
   # Validate subdomain format
   grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' targets/subdomains/*.txt
   ```

### Security Considerations

1. **Sensitive subdomain handling**
   - Use private repositories for internal assets
   - Implement access controls on target files
   - Consider subdomain anonymization for reporting

2. **Rate limiting**
   - Configure appropriate scan intervals
   - Implement backoff strategies for failed scans
   - Monitor resource usage

3. **Alert fatigue prevention**
   - Use different alert channels for different priorities
   - Implement alert grouping
   - Configure escalation policies

### Operational Excellence

1. **Documentation**
   - Document subdomain naming conventions
   - Maintain discovery tool configurations
   - Keep integration guides updated

2. **Automation**
   - Automate subdomain discovery processes
   - Implement automated validation
   - Use infrastructure as code principles

3. **Monitoring**
   - Track discovery effectiveness
   - Monitor scan coverage
   - Measure response times

This integration transforms your security scanning from static, manual target management to dynamic, automated coverage that scales with your infrastructure discovery.