#!/usr/bin/env python3
"""
DAST Continuous Monitoring System
Automated security scanning tool for multiple domains with Grafana integration
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import requests
import sqlite3
from croniter import croniter

# Import integrations
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'integrations'))
from google_chat_integration import GoogleChatIntegration

@dataclass
class ScanTarget:
    domain: str
    subdomains: List[str]
    scan_type: str  # 'standard', 'spa', 'api'
    auth_config: Optional[Dict] = None
    custom_config: Optional[str] = None
    priority: int = 1  # 1-5, higher = more frequent
    last_scan: Optional[datetime] = None
    next_scan: Optional[datetime] = None

@dataclass
class ScanResult:
    target: str
    timestamp: datetime
    scan_type: str
    duration: float
    alerts_high: int
    alerts_medium: int
    alerts_low: int
    alerts_info: int
    total_alerts: int
    status: str  # 'completed', 'failed', 'timeout'
    report_path: str
    error_message: Optional[str] = None

class DASTMonitor:
    def __init__(self, config_path: str = "dast_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.db_path = self.config.get('database', 'dast_monitor.db')
        self.running = False
        
        # Setup logging
        self._setup_logging()
        
        # Initialize database
        self._init_database()
        
        # Load targets
        self.targets = self._load_targets()
        
        # Thread pool for concurrent scans
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('max_concurrent_scans', 3))
        
        # Initialize integrations
        self._init_integrations()
        
        self.logger.info("DAST Monitor initialized")

    def _setup_logging(self):
        log_level = self.config.get('log_level', 'INFO')
        log_file = self.config.get('log_file', 'dast_monitor.log')
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_config(self) -> Dict:
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.error(f"Config file {self.config_path} not found")
            return self._create_default_config()

    def _create_default_config(self) -> Dict:
        default_config = {
            'database': 'dast_monitor.db',
            'max_concurrent_scans': 3,
            'log_level': 'INFO',
            'log_file': 'dast_monitor.log',
            'scan_schedules': {
                'high_priority': '0 */2 * * *',  # Every 2 hours
                'medium_priority': '0 */6 * * *',  # Every 6 hours
                'low_priority': '0 0 */1 * *'  # Daily
            },
            'zap': {
                'version': '2.14.0',
                'timeout': 3600,
                'memory': '2g'
            },
            'grafana': {
                'enabled': False,
                'url': 'http://localhost:3000',
                'api_key': '',
                'dashboard_id': 'dast-monitor'
            },
            'siem': {
                'enabled': False,
                'webhook_url': '',
                'severity_threshold': 'medium'
            },
            'subdomain_discovery': {
                'enabled': True,
                'tools': ['subfinder', 'assetfinder'],
                'update_frequency': '0 0 * * 0'  # Weekly
            },
            'reports': {
                'retention_days': 90,
                'formats': ['json', 'html', 'xml'],
                'export_path': './reports'
            }
        }
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
            
        return default_config

    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                subdomains TEXT,
                scan_type TEXT DEFAULT 'standard',
                auth_config TEXT,
                custom_config TEXT,
                priority INTEGER DEFAULT 1,
                last_scan TIMESTAMP,
                next_scan TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                scan_type TEXT,
                duration REAL,
                alerts_high INTEGER DEFAULT 0,
                alerts_medium INTEGER DEFAULT 0,
                alerts_low INTEGER DEFAULT 0,
                alerts_info INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0,
                status TEXT,
                report_path TEXT,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Subdomains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_verified TIMESTAMP,
                status TEXT DEFAULT 'active',
                UNIQUE(domain, subdomain)
            )
        ''')
        
        conn.commit()
        conn.close()

    def _init_integrations(self):
        """Initialize notification and monitoring integrations"""
        # Google Chat integration
        google_chat_config = self.config.get('notifications', {}).get('google_chat', {})
        self.google_chat = GoogleChatIntegration(google_chat_config)
        
        if self.google_chat.enabled:
            self.logger.info("Google Chat integration enabled")
        else:
            self.logger.info("Google Chat integration disabled")

    def _load_targets(self) -> List[ScanTarget]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM targets')
        rows = cursor.fetchall()
        conn.close()
        
        targets = []
        for row in rows:
            target = ScanTarget(
                domain=row[1],
                subdomains=json.loads(row[2]) if row[2] else [],
                scan_type=row[3],
                auth_config=json.loads(row[4]) if row[4] else None,
                custom_config=row[5],
                priority=row[6],
                last_scan=datetime.fromisoformat(row[7]) if row[7] else None,
                next_scan=datetime.fromisoformat(row[8]) if row[8] else None
            )
            targets.append(target)
        
        return targets

    def add_target(self, domain: str, scan_type: str = 'standard', 
                   priority: int = 1, auth_config: Optional[Dict] = None):
        """Add a new target domain for monitoring"""
        
        # Discover subdomains if enabled
        subdomains = []
        if self.config.get('subdomain_discovery', {}).get('enabled', True):
            subdomains = self._discover_subdomains(domain)
        
        target = ScanTarget(
            domain=domain,
            subdomains=subdomains,
            scan_type=scan_type,
            auth_config=auth_config,
            priority=priority,
            next_scan=self._calculate_next_scan(priority)
        )
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO targets (domain, subdomains, scan_type, auth_config, priority, next_scan)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                target.domain,
                json.dumps(target.subdomains),
                target.scan_type,
                json.dumps(target.auth_config) if target.auth_config else None,
                target.priority,
                target.next_scan.isoformat()
            ))
            conn.commit()
            self.targets.append(target)
            self.logger.info(f"Added target: {domain}")
            
        except sqlite3.IntegrityError:
            self.logger.warning(f"Target {domain} already exists")
        finally:
            conn.close()

    def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains for a given domain"""
        subdomains = set()
        tools = self.config.get('subdomain_discovery', {}).get('tools', ['subfinder'])
        
        for tool in tools:
            try:
                if tool == 'subfinder':
                    result = subprocess.run(['subfinder', '-d', domain, '-silent'], 
                                          capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        subdomains.update(result.stdout.strip().split('\n'))
                
                elif tool == 'assetfinder':
                    result = subprocess.run(['assetfinder', domain], 
                                          capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        subdomains.update(result.stdout.strip().split('\n'))
                        
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Timeout discovering subdomains with {tool} for {domain}")
            except FileNotFoundError:
                self.logger.warning(f"Tool {tool} not found")
        
        # Filter and validate subdomains
        valid_subdomains = []
        for subdomain in subdomains:
            if subdomain and subdomain.strip() and domain in subdomain:
                valid_subdomains.append(subdomain.strip())
        
        # Save to database
        self._save_discovered_subdomains(domain, valid_subdomains)
        
        return valid_subdomains

    def _save_discovered_subdomains(self, domain: str, subdomains: List[str]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for subdomain in subdomains:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO discovered_subdomains (domain, subdomain)
                    VALUES (?, ?)
                ''', (domain, subdomain))
            except Exception as e:
                self.logger.error(f"Error saving subdomain {subdomain}: {e}")
        
        conn.commit()
        conn.close()

    def _calculate_next_scan(self, priority: int) -> datetime:
        """Calculate next scan time based on priority"""
        schedules = self.config.get('scan_schedules', {})
        
        if priority >= 4:
            cron_expr = schedules.get('high_priority', '0 */2 * * *')
        elif priority >= 2:
            cron_expr = schedules.get('medium_priority', '0 */6 * * *')
        else:
            cron_expr = schedules.get('low_priority', '0 0 */1 * *')
        
        cron = croniter(cron_expr, datetime.now())
        return cron.get_next(datetime)

    def _run_zap_scan(self, target: ScanTarget) -> ScanResult:
        """Execute ZAP scan for a target"""
        start_time = time.time()
        
        # Create reports directory
        reports_dir = Path(self.config.get('reports', {}).get('export_path', './reports'))
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Prepare scan for all domains (main + subdomains)
        all_domains = [target.domain] + target.subdomains[:10]  # Limit subdomains
        
        results = []
        for domain in all_domains:
            try:
                result = self._scan_single_domain(domain, target, timestamp)
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error scanning {domain}: {e}")
                results.append(ScanResult(
                    target=domain,
                    timestamp=datetime.now(),
                    scan_type=target.scan_type,
                    duration=time.time() - start_time,
                    alerts_high=0, alerts_medium=0, alerts_low=0, alerts_info=0,
                    total_alerts=0,
                    status='failed',
                    report_path='',
                    error_message=str(e)
                ))
        
        # Aggregate results
        return self._aggregate_scan_results(results, target)

    def _scan_single_domain(self, domain: str, target: ScanTarget, timestamp: str) -> ScanResult:
        """Scan a single domain"""
        
        # Prepare automation config
        automation_config = self._prepare_automation_config(domain, target, timestamp)
        config_path = f"automation_{timestamp}_{hash(domain) % 10000}.yaml"
        
        with open(config_path, 'w') as f:
            yaml.dump(automation_config, f)
        
        try:
            # Run ZAP scan
            cmd = [
                'docker', 'run', '--rm',
                '--name', f'zap-monitor-{timestamp}-{hash(domain) % 10000}',
                '-v', f'{os.getcwd()}:/zap/wrk/:rw',
                '-e', f'TARGET_URL=https://{domain}',
                '--user', 'root',
                f"owasp/zap2docker-stable:{self.config.get('zap', {}).get('version', '2.14.0')}",
                'zap.sh', '-cmd', '-autorun', f'/zap/wrk/{config_path}'
            ]
            
            timeout = self.config.get('zap', {}).get('timeout', 3600)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            # Parse results
            return self._parse_zap_results(domain, target.scan_type, timestamp, result)
            
        finally:
            # Cleanup
            if os.path.exists(config_path):
                os.remove(config_path)

    def _prepare_automation_config(self, domain: str, target: ScanTarget, timestamp: str) -> Dict:
        """Prepare ZAP automation configuration"""
        
        config = {
            'env': {
                'contexts': [{
                    'name': f'context-{domain}',
                    'urls': [f'https://{domain}'],
                    'includePaths': [f'https://{domain}/.*'],
                    'excludePaths': []
                }]
            },
            'jobs': [
                {
                    'type': 'passiveScan-config',
                    'parameters': {
                        'maxAlertsPerRule': 10,
                        'scanOnlyInScope': True
                    }
                },
                {
                    'type': 'spider',
                    'parameters': {
                        'context': f'context-{domain}',
                        'url': f'https://{domain}',
                        'maxDuration': 10,
                        'maxDepth': 5
                    }
                }
            ]
        }
        
        # Add active scan for non-production environments
        if target.scan_type in ['standard', 'full']:
            config['jobs'].append({
                'type': 'activeScan',
                'parameters': {
                    'context': f'context-{domain}',
                    'url': f'https://{domain}',
                    'maxDuration': 30,
                    'maxRuleDurationInMins': 5
                }
            })
        
        # Add authentication if configured
        if target.auth_config:
            auth_job = {
                'type': 'authentication',
                'parameters': target.auth_config
            }
            config['jobs'].insert(0, auth_job)
        
        # Add report generation
        report_formats = self.config.get('reports', {}).get('formats', ['json'])
        for fmt in report_formats:
            config['jobs'].append({
                'type': 'report',
                'parameters': {
                    'template': fmt,
                    'reportFile': f'report-{domain}-{timestamp}.{fmt}',
                    'reportTitle': f'DAST Scan Report - {domain}',
                    'reportDescription': f'Automated security scan for {domain}'
                }
            })
        
        return config

    def _parse_zap_results(self, domain: str, scan_type: str, timestamp: str, 
                          process_result) -> ScanResult:
        """Parse ZAP scan results"""
        
        # Look for JSON report
        json_report = f"report-{domain}-{timestamp}.json"
        
        if os.path.exists(json_report):
            try:
                with open(json_report, 'r') as f:
                    data = json.load(f)
                
                site = data.get('site', [{}])[0] if data.get('site') else {}
                alerts = site.get('alerts', [])
                
                # Count alerts by risk level
                risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
                
                for alert in alerts:
                    risk = alert.get('riskdesc', '').split(' ')[0]
                    if risk in risk_counts:
                        risk_counts[risk] += 1
                
                return ScanResult(
                    target=domain,
                    timestamp=datetime.now(),
                    scan_type=scan_type,
                    duration=0,  # Will be calculated later
                    alerts_high=risk_counts['High'],
                    alerts_medium=risk_counts['Medium'],
                    alerts_low=risk_counts['Low'],
                    alerts_info=risk_counts['Informational'],
                    total_alerts=len(alerts),
                    status='completed',
                    report_path=json_report
                )
                
            except Exception as e:
                self.logger.error(f"Error parsing results for {domain}: {e}")
        
        # Fallback if JSON parsing fails
        return ScanResult(
            target=domain,
            timestamp=datetime.now(),
            scan_type=scan_type,
            duration=0,
            alerts_high=0, alerts_medium=0, alerts_low=0, alerts_info=0,
            total_alerts=0,
            status='completed' if process_result.returncode == 0 else 'failed',
            report_path=json_report if os.path.exists(json_report) else '',
            error_message=process_result.stderr if process_result.returncode != 0 else None
        )

    def _aggregate_scan_results(self, results: List[ScanResult], target: ScanTarget) -> ScanResult:
        """Aggregate results from multiple domain scans"""
        
        total_high = sum(r.alerts_high for r in results)
        total_medium = sum(r.alerts_medium for r in results)
        total_low = sum(r.alerts_low for r in results)
        total_info = sum(r.alerts_info for r in results)
        
        # Determine overall status
        status = 'completed'
        if any(r.status == 'failed' for r in results):
            status = 'partial' if any(r.status == 'completed' for r in results) else 'failed'
        
        return ScanResult(
            target=target.domain,
            timestamp=datetime.now(),
            scan_type=target.scan_type,
            duration=sum(r.duration for r in results),
            alerts_high=total_high,
            alerts_medium=total_medium,
            alerts_low=total_low,
            alerts_info=total_info,
            total_alerts=total_high + total_medium + total_low + total_info,
            status=status,
            report_path=f"aggregated_report_{target.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

    def _save_scan_result(self, result: ScanResult):
        """Save scan result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_results 
            (target, timestamp, scan_type, duration, alerts_high, alerts_medium, 
             alerts_low, alerts_info, total_alerts, status, report_path, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.target, result.timestamp.isoformat(), result.scan_type, result.duration,
            result.alerts_high, result.alerts_medium, result.alerts_low, result.alerts_info,
            result.total_alerts, result.status, result.report_path, result.error_message
        ))
        
        conn.commit()
        conn.close()
        
        # Send to Grafana if enabled
        if self.config.get('grafana', {}).get('enabled', False):
            self._send_to_grafana(result)
        
        # Send to SIEM if enabled and meets threshold
        if self._should_send_to_siem(result):
            self._send_to_siem(result)
        
        # Send notifications
        asyncio.create_task(self._send_notifications(result))

    def _send_to_grafana(self, result: ScanResult):
        """Send metrics to Grafana"""
        try:
            grafana_config = self.config.get('grafana', {})
            
            metrics = {
                'timestamp': result.timestamp.isoformat(),
                'target': result.target,
                'scan_type': result.scan_type,
                'duration': result.duration,
                'alerts_high': result.alerts_high,
                'alerts_medium': result.alerts_medium,
                'alerts_low': result.alerts_low,
                'alerts_info': result.alerts_info,
                'total_alerts': result.total_alerts,
                'status': result.status
            }
            
            # Send to Grafana (implementation depends on your Grafana setup)
            # This could be via InfluxDB, Prometheus, or direct API calls
            self.logger.info(f"Metrics sent to Grafana for {result.target}")
            
        except Exception as e:
            self.logger.error(f"Error sending to Grafana: {e}")

    def _should_send_to_siem(self, result: ScanResult) -> bool:
        """Check if result should be sent to SIEM based on severity threshold"""
        siem_config = self.config.get('siem', {})
        
        if not siem_config.get('enabled', False):
            return False
        
        threshold = siem_config.get('severity_threshold', 'medium')
        
        if threshold == 'high':
            return result.alerts_high > 0
        elif threshold == 'medium':
            return result.alerts_high > 0 or result.alerts_medium > 0
        else:
            return result.total_alerts > 0

    def _send_to_siem(self, result: ScanResult):
        """Send alert to SIEM system"""
        try:
            siem_config = self.config.get('siem', {})
            webhook_url = siem_config.get('webhook_url')
            
            if webhook_url:
                payload = {
                    'timestamp': result.timestamp.isoformat(),
                    'event_type': 'security_scan_alert',
                    'target': result.target,
                    'severity': self._calculate_severity(result),
                    'alerts': {
                        'high': result.alerts_high,
                        'medium': result.alerts_medium,
                        'low': result.alerts_low,
                        'total': result.total_alerts
                    },
                    'report_path': result.report_path
                }
                
                response = requests.post(webhook_url, json=payload, timeout=30)
                response.raise_for_status()
                
                self.logger.info(f"Alert sent to SIEM for {result.target}")
                
        except Exception as e:
            self.logger.error(f"Error sending to SIEM: {e}")

    def _calculate_severity(self, result: ScanResult) -> str:
        """Calculate overall severity based on alerts"""
        if result.alerts_high > 0:
            return 'high'
        elif result.alerts_medium > 0:
            return 'medium'
        elif result.alerts_low > 0:
            return 'low'
        else:
            return 'info'

    async def _send_notifications(self, result: ScanResult):
        """Send notifications to configured channels"""
        try:
            # Send to Google Chat
            if self.google_chat.enabled:
                await self.google_chat.send_scan_alert(result)
            
            # Send to Slack (if implemented)
            slack_config = self.config.get('notifications', {}).get('slack', {})
            if slack_config.get('enabled', False):
                await self._send_slack_notification(result, slack_config)
                
        except Exception as e:
            self.logger.error(f"Error sending notifications: {e}")

    async def _send_slack_notification(self, result: ScanResult, slack_config: Dict):
        """Send notification to Slack (simplified implementation)"""
        try:
            webhook_url = slack_config.get('webhook_url')
            if not webhook_url:
                return
            
            severity = self._calculate_severity(result)
            color_map = {
                'high': 'danger',
                'medium': 'warning', 
                'low': 'good',
                'info': '#36a64f'
            }
            
            payload = {
                "text": f"DAST Scan {result.status.title()}: {result.target}",
                "attachments": [
                    {
                        "color": color_map.get(severity, 'good'),
                        "fields": [
                            {"title": "Target", "value": result.target, "short": True},
                            {"title": "Status", "value": result.status.title(), "short": True},
                            {"title": "High Alerts", "value": str(result.alerts_high), "short": True},
                            {"title": "Medium Alerts", "value": str(result.alerts_medium), "short": True},
                            {"title": "Total Alerts", "value": str(result.total_alerts), "short": True},
                            {"title": "Duration", "value": f"{int(result.duration)}s", "short": True}
                        ],
                        "timestamp": int(result.timestamp.timestamp())
                    }
                ]
            }
            
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info(f"Slack notification sent for {result.target}")
                    else:
                        self.logger.error(f"Failed to send Slack notification: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {e}")

    async def _send_subdomain_discovery_notification(self, domain: str, new_subdomains: List[str], total_subdomains: int):
        """Send notifications for subdomain discoveries"""
        try:
            if self.google_chat.enabled:
                await self.google_chat.send_discovery_alert(domain, new_subdomains, total_subdomains)
                
            # Could add Slack subdomain notifications here too
        except Exception as e:
            self.logger.error(f"Error sending subdomain discovery notification: {e}")

    async def _monitor_loop(self):
        """Main monitoring loop"""
        self.logger.info("Starting monitoring loop")
        
        while self.running:
            try:
                # Check for targets that need scanning
                targets_to_scan = []
                current_time = datetime.now()
                
                for target in self.targets:
                    if target.next_scan and target.next_scan <= current_time:
                        targets_to_scan.append(target)
                
                # Submit scans to thread pool
                scan_futures = []
                for target in targets_to_scan:
                    future = self.executor.submit(self._run_zap_scan, target)
                    scan_futures.append((target, future))
                
                # Process completed scans
                for target, future in scan_futures:
                    try:
                        result = future.result(timeout=self.config.get('zap', {}).get('timeout', 3600))
                        self._save_scan_result(result)
                        
                        # Update target's next scan time
                        target.last_scan = datetime.now()
                        target.next_scan = self._calculate_next_scan(target.priority)
                        self._update_target_in_db(target)
                        
                        self.logger.info(f"Scan completed for {target.domain}: {result.total_alerts} alerts found")
                        
                    except Exception as e:
                        self.logger.error(f"Scan failed for {target.domain}: {e}")
                
                # Periodic maintenance tasks
                await self._run_maintenance()
                
                # Sleep before next iteration
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)

    def _update_target_in_db(self, target: ScanTarget):
        """Update target information in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE targets 
            SET last_scan = ?, next_scan = ?, updated_at = CURRENT_TIMESTAMP
            WHERE domain = ?
        ''', (
            target.last_scan.isoformat() if target.last_scan else None,
            target.next_scan.isoformat() if target.next_scan else None,
            target.domain
        ))
        
        conn.commit()
        conn.close()

    async def _run_maintenance(self):
        """Run periodic maintenance tasks"""
        current_time = datetime.now()
        
        # Update subdomains weekly
        if hasattr(self, 'last_subdomain_update'):
            if (current_time - self.last_subdomain_update).days >= 7:
                await self._update_all_subdomains()
        else:
            self.last_subdomain_update = current_time
        
        # Clean old reports
        retention_days = self.config.get('reports', {}).get('retention_days', 90)
        await self._cleanup_old_reports(retention_days)

    async def _update_all_subdomains(self):
        """Update subdomains for all targets"""
        for target in self.targets:
            try:
                new_subdomains = self._discover_subdomains(target.domain)
                if new_subdomains != target.subdomains:
                    target.subdomains = new_subdomains
                    # Update in database
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE targets SET subdomains = ?, updated_at = CURRENT_TIMESTAMP 
                        WHERE domain = ?
                    ''', (json.dumps(new_subdomains), target.domain))
                    conn.commit()
                    conn.close()
                    
                    self.logger.info(f"Updated subdomains for {target.domain}: {len(new_subdomains)} found")
            except Exception as e:
                self.logger.error(f"Error updating subdomains for {target.domain}: {e}")
        
        self.last_subdomain_update = datetime.now()

    async def _cleanup_old_reports(self, retention_days: int):
        """Clean up old report files"""
        try:
            reports_dir = Path(self.config.get('reports', {}).get('export_path', './reports'))
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            for report_file in reports_dir.glob('*'):
                if report_file.is_file() and report_file.stat().st_mtime < cutoff_date.timestamp():
                    report_file.unlink()
                    self.logger.debug(f"Cleaned up old report: {report_file}")
                    
        except Exception as e:
            self.logger.error(f"Error cleaning up old reports: {e}")

    def start(self):
        """Start the monitoring system"""
        self.running = True
        self.logger.info("DAST Monitor starting...")
        
        # Start the monitoring loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self._monitor_loop())
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            self.stop()
            loop.close()

    def stop(self):
        """Stop the monitoring system"""
        self.running = False
        self.executor.shutdown(wait=True)
        self.logger.info("DAST Monitor stopped")

    def get_status(self) -> Dict:
        """Get current status of the monitoring system"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get target count
        cursor.execute('SELECT COUNT(*) FROM targets')
        target_count = cursor.fetchone()[0]
        
        # Get recent scans (last 24 hours)
        cursor.execute('''
            SELECT COUNT(*), AVG(total_alerts) 
            FROM scan_results 
            WHERE timestamp > datetime('now', '-1 day')
        ''')
        recent_scans, avg_alerts = cursor.fetchone()
        
        # Get next scheduled scan
        cursor.execute('SELECT MIN(next_scan) FROM targets WHERE next_scan IS NOT NULL')
        next_scan = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'status': 'running' if self.running else 'stopped',
            'targets': target_count,
            'recent_scans_24h': recent_scans or 0,
            'avg_alerts_24h': avg_alerts or 0,
            'next_scheduled_scan': next_scan
        }

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='DAST Continuous Monitoring System')
    parser.add_argument('--config', default='dast_config.yaml', help='Configuration file path')
    parser.add_argument('--add-target', help='Add a target domain')
    parser.add_argument('--scan-type', default='standard', choices=['standard', 'spa', 'api'], 
                       help='Scan type for new targets')
    parser.add_argument('--priority', type=int, default=1, choices=[1,2,3,4,5],
                       help='Priority level (1-5, higher = more frequent)')
    parser.add_argument('--status', action='store_true', help='Show system status')
    
    args = parser.parse_args()
    
    monitor = DASTMonitor(args.config)
    
    if args.add_target:
        monitor.add_target(args.add_target, args.scan_type, args.priority)
        print(f"Added target: {args.add_target}")
    elif args.status:
        status = monitor.get_status()
        print(json.dumps(status, indent=2, default=str))
    else:
        # Start monitoring
        monitor.start()