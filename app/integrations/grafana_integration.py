#!/usr/bin/env python3
"""
Grafana Integration Module
Handles metrics export and dashboard management for DAST monitoring
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import requests
import asyncio
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, push_to_gateway
from prometheus_client.exposition import generate_latest
import influxdb_client
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

@dataclass
class MetricPoint:
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str]
    description: Optional[str] = None

class GrafanaIntegration:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get('enabled', False)
        
        if not self.enabled:
            self.logger.info("Grafana integration disabled")
            return
        
        self.grafana_url = config.get('url', 'http://localhost:3000')
        self.api_key = config.get('api_key', '')
        self.dashboard_id = config.get('dashboard_id', 'dast-monitor')
        self.datasource = config.get('datasource', 'prometheus')
        
        # Initialize metric collectors based on datasource
        if self.datasource == 'prometheus':
            self._init_prometheus_metrics()
        elif self.datasource == 'influxdb':
            self._init_influxdb_client()
        
        # Grafana API headers
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        self.registry = CollectorRegistry()
        
        # Core DAST metrics
        self.scan_duration = Gauge(
            'dast_scan_duration_seconds',
            'Time taken for DAST scan to complete',
            ['target', 'scan_type', 'status'],
            registry=self.registry
        )
        
        self.alerts_by_severity = Gauge(
            'dast_alerts_by_severity',
            'Number of security alerts by severity level',
            ['target', 'severity', 'scan_type'],
            registry=self.registry
        )
        
        self.total_scans = Counter(
            'dast_scans_total',
            'Total number of DAST scans performed',
            ['target', 'scan_type', 'status'],
            registry=self.registry
        )
        
        self.scan_status = Gauge(
            'dast_scan_status',
            'Current status of DAST scan (1=success, 0=failed)',
            ['target', 'scan_type'],
            registry=self.registry
        )
        
        self.targets_count = Gauge(
            'dast_targets_total',
            'Total number of targets being monitored',
            registry=self.registry
        )
        
        self.vulnerability_trend = Gauge(
            'dast_vulnerability_trend',
            'Vulnerability trend over time',
            ['target', 'severity', 'timeframe'],
            registry=self.registry
        )
        
        self.discovery_metrics = Gauge(
            'dast_subdomains_discovered',
            'Number of subdomains discovered',
            ['target', 'source'],
            registry=self.registry
        )

    def _init_influxdb_client(self):
        """Initialize InfluxDB client"""
        influx_config = self.config.get('influxdb', {})
        
        self.influx_client = InfluxDBClient(
            url=influx_config.get('url', 'http://localhost:8086'),
            token=influx_config.get('token', ''),
            org=influx_config.get('org', 'dast-monitoring'),
            timeout=30000
        )
        
        self.bucket = influx_config.get('bucket', 'dast-metrics')
        self.write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)

    def send_scan_metrics(self, scan_result) -> bool:
        """Send scan result metrics to configured datasource"""
        if not self.enabled:
            return True
        
        try:
            if self.datasource == 'prometheus':
                return self._send_prometheus_metrics(scan_result)
            elif self.datasource == 'influxdb':
                return self._send_influxdb_metrics(scan_result)
            else:
                self.logger.error(f"Unsupported datasource: {self.datasource}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send metrics: {e}")
            return False

    def _send_prometheus_metrics(self, scan_result) -> bool:
        """Send metrics to Prometheus"""
        try:
            # Update scan duration
            self.scan_duration.labels(
                target=scan_result.target,
                scan_type=scan_result.scan_type,
                status=scan_result.status
            ).set(scan_result.duration)
            
            # Update alert counts by severity
            severities = {
                'high': scan_result.alerts_high,
                'medium': scan_result.alerts_medium,
                'low': scan_result.alerts_low,
                'info': scan_result.alerts_info
            }
            
            for severity, count in severities.items():
                self.alerts_by_severity.labels(
                    target=scan_result.target,
                    severity=severity,
                    scan_type=scan_result.scan_type
                ).set(count)
            
            # Update scan counter
            self.total_scans.labels(
                target=scan_result.target,
                scan_type=scan_result.scan_type,
                status=scan_result.status
            ).inc()
            
            # Update scan status (1 for success, 0 for failed)
            status_value = 1 if scan_result.status == 'completed' else 0
            self.scan_status.labels(
                target=scan_result.target,
                scan_type=scan_result.scan_type
            ).set(status_value)
            
            # Push to Prometheus gateway if configured
            gateway_url = self.config.get('prometheus', {}).get('gateway_url')
            if gateway_url:
                job_name = f'dast-monitor-{scan_result.target}'
                push_to_gateway(gateway_url, job=job_name, registry=self.registry)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Prometheus metrics: {e}")
            return False

    def _send_influxdb_metrics(self, scan_result) -> bool:
        """Send metrics to InfluxDB"""
        try:
            points = []
            timestamp = scan_result.timestamp
            
            # Scan duration metric
            points.append(
                Point("dast_scan_duration")
                .tag("target", scan_result.target)
                .tag("scan_type", scan_result.scan_type)
                .tag("status", scan_result.status)
                .field("duration_seconds", scan_result.duration)
                .time(timestamp)
            )
            
            # Alert metrics by severity
            alert_fields = {
                "alerts_high": scan_result.alerts_high,
                "alerts_medium": scan_result.alerts_medium,
                "alerts_low": scan_result.alerts_low,
                "alerts_info": scan_result.alerts_info,
                "alerts_total": scan_result.total_alerts
            }
            
            point = Point("dast_alerts").tag("target", scan_result.target).tag("scan_type", scan_result.scan_type)
            for field, value in alert_fields.items():
                point = point.field(field, value)
            points.append(point.time(timestamp))
            
            # Scan status metric
            points.append(
                Point("dast_scan_status")
                .tag("target", scan_result.target)
                .tag("scan_type", scan_result.scan_type)
                .field("status", 1 if scan_result.status == 'completed' else 0)
                .field("success", scan_result.status == 'completed')
                .time(timestamp)
            )
            
            # Write points to InfluxDB
            self.write_api.write(bucket=self.bucket, record=points)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send InfluxDB metrics: {e}")
            return False

    def send_discovery_metrics(self, domain: str, subdomains_by_source: Dict[str, int]):
        """Send subdomain discovery metrics"""
        if not self.enabled:
            return
        
        try:
            if self.datasource == 'prometheus':
                for source, count in subdomains_by_source.items():
                    self.discovery_metrics.labels(
                        target=domain,
                        source=source
                    ).set(count)
            
            elif self.datasource == 'influxdb':
                points = []
                timestamp = datetime.utcnow()
                
                for source, count in subdomains_by_source.items():
                    points.append(
                        Point("dast_subdomains_discovered")
                        .tag("target", domain)
                        .tag("source", source)
                        .field("count", count)
                        .time(timestamp)
                    )
                
                self.write_api.write(bucket=self.bucket, record=points)
                
        except Exception as e:
            self.logger.error(f"Failed to send discovery metrics: {e}")

    def update_targets_count(self, count: int):
        """Update total targets count metric"""
        if not self.enabled:
            return
        
        try:
            if self.datasource == 'prometheus':
                self.targets_count.set(count)
            elif self.datasource == 'influxdb':
                point = Point("dast_targets_total").field("count", count).time(datetime.utcnow())
                self.write_api.write(bucket=self.bucket, record=point)
                
        except Exception as e:
            self.logger.error(f"Failed to update targets count: {e}")

    def send_vulnerability_trend(self, target: str, trend_data: Dict[str, Dict[str, int]]):
        """Send vulnerability trend data"""
        if not self.enabled:
            return
        
        try:
            if self.datasource == 'prometheus':
                for timeframe, severities in trend_data.items():
                    for severity, count in severities.items():
                        self.vulnerability_trend.labels(
                            target=target,
                            severity=severity,
                            timeframe=timeframe
                        ).set(count)
            
            elif self.datasource == 'influxdb':
                points = []
                timestamp = datetime.utcnow()
                
                for timeframe, severities in trend_data.items():
                    point = Point("dast_vulnerability_trend").tag("target", target).tag("timeframe", timeframe)
                    for severity, count in severities.items():
                        point = point.field(f"alerts_{severity}", count)
                    points.append(point.time(timestamp))
                
                self.write_api.write(bucket=self.bucket, record=points)
                
        except Exception as e:
            self.logger.error(f"Failed to send vulnerability trend: {e}")

    def create_dashboard(self) -> bool:
        """Create or update Grafana dashboard"""
        if not self.enabled:
            return True
        
        try:
            dashboard_config = self._get_dashboard_config()
            
            # Check if dashboard exists
            dashboard_uid = self._get_dashboard_uid()
            if dashboard_uid:
                # Update existing dashboard
                response = requests.put(
                    f"{self.grafana_url}/api/dashboards/db",
                    headers=self.headers,
                    json=dashboard_config
                )
            else:
                # Create new dashboard
                response = requests.post(
                    f"{self.grafana_url}/api/dashboards/db",
                    headers=self.headers,
                    json=dashboard_config
                )
            
            if response.status_code in [200, 201]:
                self.logger.info("Dashboard created/updated successfully")
                return True
            else:
                self.logger.error(f"Failed to create dashboard: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to create dashboard: {e}")
            return False

    def _get_dashboard_uid(self) -> Optional[str]:
        """Get existing dashboard UID"""
        try:
            response = requests.get(
                f"{self.grafana_url}/api/dashboards/uid/{self.dashboard_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                return response.json().get('dashboard', {}).get('uid')
            return None
            
        except Exception as e:
            self.logger.debug(f"Dashboard not found: {e}")
            return None

    def _get_dashboard_config(self) -> Dict:
        """Generate Grafana dashboard configuration"""
        return {
            "dashboard": {
                "id": None,
                "uid": self.dashboard_id,
                "title": "DAST Security Monitoring",
                "tags": ["security", "dast", "vulnerability"],
                "timezone": "browser",
                "refresh": "30s",
                "time": {
                    "from": "now-24h",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "Scan Overview",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "sum(dast_scans_total)",
                                "legendFormat": "Total Scans"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Active Targets",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "dast_targets_total",
                                "legendFormat": "Monitored Targets"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "High Severity Alerts",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": 'sum(dast_alerts_by_severity{severity="high"})',
                                "legendFormat": "Critical Issues"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "color": {"mode": "palette-classic"},
                                "custom": {"displayMode": "basic"},
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": None},
                                        {"color": "red", "value": 1}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0}
                    },
                    {
                        "id": 4,
                        "title": "Scan Success Rate",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": 'sum(rate(dast_scans_total{status="completed"}[5m])) / sum(rate(dast_scans_total[5m])) * 100',
                                "legendFormat": "Success Rate %"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
                    },
                    {
                        "id": 5,
                        "title": "Alerts by Severity Over Time",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": 'sum by (severity) (dast_alerts_by_severity)',
                                "legendFormat": "{{severity}}"
                            }
                        ],
                        "yAxes": [
                            {"label": "Alert Count", "min": 0},
                            {"show": False}
                        ],
                        "gridPos": {"h": 9, "w": 12, "x": 0, "y": 8}
                    },
                    {
                        "id": 6,
                        "title": "Scan Duration by Target",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "dast_scan_duration_seconds",
                                "legendFormat": "{{target}} ({{scan_type}})"
                            }
                        ],
                        "yAxes": [
                            {"label": "Duration (seconds)", "min": 0},
                            {"show": False}
                        ],
                        "gridPos": {"h": 9, "w": 12, "x": 12, "y": 8}
                    },
                    {
                        "id": 7,
                        "title": "Target Status Heatmap",
                        "type": "heatmap",
                        "targets": [
                            {
                                "expr": "dast_scan_status",
                                "format": "heatmap",
                                "legendFormat": "{{target}}"
                            }
                        ],
                        "gridPos": {"h": 9, "w": 24, "x": 0, "y": 17}
                    },
                    {
                        "id": 8,
                        "title": "Recent Scan Results",
                        "type": "table",
                        "targets": [
                            {
                                "expr": "dast_scan_status",
                                "format": "table",
                                "instant": True
                            }
                        ],
                        "transformations": [
                            {
                                "id": "organize",
                                "options": {
                                    "excludeByName": {},
                                    "indexByName": {},
                                    "renameByName": {
                                        "target": "Target",
                                        "scan_type": "Scan Type",
                                        "Value": "Status"
                                    }
                                }
                            }
                        ],
                        "gridPos": {"h": 9, "w": 24, "x": 0, "y": 26}
                    }
                ],
                "templating": {
                    "list": [
                        {
                            "name": "target",
                            "type": "query",
                            "query": "label_values(dast_scan_status, target)",
                            "current": {"selected": False, "text": "All", "value": "$__all"},
                            "includeAll": True,
                            "multi": True
                        }
                    ]
                },
                "annotations": {
                    "list": [
                        {
                            "name": "High Severity Alerts",
                            "datasource": self.datasource,
                            "enable": True,
                            "expr": 'changes(dast_alerts_by_severity{severity="high"}[1m]) > 0',
                            "iconColor": "red",
                            "titleFormat": "High severity alert detected"
                        }
                    ]
                }
            },
            "overwrite": True
        }

    def create_alerting_rules(self) -> bool:
        """Create alerting rules in Grafana"""
        if not self.enabled:
            return True
        
        try:
            alert_rules = [
                {
                    "uid": "dast-high-severity-alert",
                    "title": "DAST High Severity Vulnerabilities",
                    "condition": "A",
                    "data": [
                        {
                            "refId": "A",
                            "queryType": "",
                            "relativeTimeRange": {"from": 600, "to": 0},
                            "model": {
                                "expr": 'sum(dast_alerts_by_severity{severity="high"}) > 0',
                                "interval": "",
                                "refId": "A"
                            }
                        }
                    ],
                    "noDataState": "NoData",
                    "execErrState": "Alerting",
                    "for": "1m",
                    "annotations": {
                        "description": "High severity vulnerabilities detected in DAST scan",
                        "summary": "Critical security issues found"
                    },
                    "labels": {"team": "security", "severity": "critical"}
                },
                {
                    "uid": "dast-scan-failure-alert", 
                    "title": "DAST Scan Failures",
                    "condition": "A",
                    "data": [
                        {
                            "refId": "A",
                            "queryType": "",
                            "relativeTimeRange": {"from": 300, "to": 0},
                            "model": {
                                "expr": 'sum(rate(dast_scans_total{status="failed"}[5m])) > 0',
                                "interval": "",
                                "refId": "A"
                            }
                        }
                    ],
                    "noDataState": "NoData",
                    "execErrState": "Alerting",
                    "for": "2m",
                    "annotations": {
                        "description": "DAST scans are failing",
                        "summary": "Scan failure detected"
                    },
                    "labels": {"team": "security", "severity": "warning"}
                }
            ]
            
            # Create alert rules (this would require Grafana 9+ unified alerting API)
            for rule in alert_rules:
                response = requests.post(
                    f"{self.grafana_url}/api/v1/provisioning/alert-rules",
                    headers=self.headers,
                    json=rule
                )
                
                if response.status_code not in [200, 201]:
                    self.logger.warning(f"Failed to create alert rule {rule['title']}: {response.text}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create alerting rules: {e}")
            return False

    def get_metrics_endpoint(self) -> str:
        """Get Prometheus metrics endpoint"""
        if self.datasource == 'prometheus':
            return generate_latest(self.registry).decode('utf-8')
        else:
            return "Metrics only available for Prometheus datasource"

    def test_connection(self) -> bool:
        """Test connection to Grafana"""
        try:
            response = requests.get(
                f"{self.grafana_url}/api/health",
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Grafana connection test successful")
                return True
            else:
                self.logger.error(f"Grafana connection failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Grafana connection test failed: {e}")
            return False

    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'influx_client'):
            self.influx_client.close()

async def main():
    """Test Grafana integration"""
    config = {
        'enabled': True,
        'url': 'http://localhost:3000',
        'api_key': 'test-key',
        'datasource': 'prometheus'
    }
    
    grafana = GrafanaIntegration(config)
    
    # Test connection
    if grafana.test_connection():
        print("✓ Grafana connection successful")
    else:
        print("✗ Grafana connection failed")
    
    # Create dashboard
    if grafana.create_dashboard():
        print("✓ Dashboard created successfully")
    else:
        print("✗ Dashboard creation failed")

if __name__ == '__main__':
    asyncio.run(main())