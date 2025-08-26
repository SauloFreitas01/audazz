#!/usr/bin/env python3
"""
SIEM/SOAR Integration Module
Handles security event forwarding to various SIEM platforms
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
import hashlib
import hmac
import base64

import requests
import aiohttp
from splunk_hec import SplunkHECHandler
from elasticsearch import AsyncElasticsearch, Elasticsearch
import boto3


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    INFO = "info"

class AlertType(Enum):
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    HIGH_RISK_FINDING = "high_risk_finding"
    NEW_SUBDOMAIN_DISCOVERED = "new_subdomain_discovered"
    SCAN_THRESHOLD_EXCEEDED = "scan_threshold_exceeded"

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: AlertType
    severity: SeverityLevel
    source: str
    target: str
    title: str
    description: str
    raw_data: Dict[str, Any]
    remediation: Optional[str] = None
    cve_references: List[str] = None
    mitre_tactics: List[str] = None
    confidence_score: float = 1.0
    false_positive_likelihood: float = 0.0

class SIEMIntegration:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get('enabled', False)
        
        if not self.enabled:
            self.logger.info("SIEM integration disabled")
            return
        
        self.severity_threshold = SeverityLevel(config.get('severity_threshold', 'medium'))
        self.siem_type = config.get('type', 'webhook')
        
        # Initialize specific SIEM clients
        self._init_siem_clients()

    def _init_siem_clients(self):
        """Initialize SIEM-specific clients"""
        try:
            if self.siem_type == 'splunk':
                self._init_splunk()
            elif self.siem_type == 'elasticsearch':
                self._init_elasticsearch()
            elif self.siem_type == 'sentinel':
                self._init_azure_sentinel()
            elif self.siem_type == 'qradar':
                self._init_qradar()
            elif self.siem_type == 'webhook':
                self._init_webhook()
        except Exception as e:
            self.logger.error(f"Failed to initialize SIEM client: {e}")

    def _init_splunk(self):
        """Initialize Splunk HEC client"""
        splunk_config = self.config.get('splunk', {})
        self.splunk_host = splunk_config.get('host', 'localhost')
        self.splunk_port = splunk_config.get('port', 8088)
        self.splunk_token = splunk_config.get('token', '')
        self.splunk_index = splunk_config.get('index', 'security')
        
        if self.splunk_token:
            self.splunk_handler = SplunkHECHandler(
                host=self.splunk_host,
                port=self.splunk_port,
                token=self.splunk_token,
                index=self.splunk_index,
                source='dast-monitor',
                sourcetype='security:scan'
            )

    def _init_elasticsearch(self):
        """Initialize Elasticsearch client"""
        es_config = self.config.get('elasticsearch', {})
        hosts = es_config.get('hosts', ['localhost:9200'])
        
        auth_config = es_config.get('auth', {})
        if auth_config.get('username') and auth_config.get('password'):
            auth = (auth_config['username'], auth_config['password'])
        else:
            auth = None
        
        self.es_client = AsyncElasticsearch(
            hosts=hosts,
            http_auth=auth,
            verify_certs=es_config.get('verify_certs', False),
            ssl_show_warn=es_config.get('ssl_show_warn', False)
        )
        
        self.es_index = es_config.get('index', 'dast-alerts')

    def _init_azure_sentinel(self):
        """Initialize Azure Sentinel client"""
        sentinel_config = self.config.get('sentinel', {})
        self.sentinel_workspace_id = sentinel_config.get('workspace_id', '')
        self.sentinel_shared_key = sentinel_config.get('shared_key', '')
        self.sentinel_log_type = sentinel_config.get('log_type', 'DASTScan')

    def _init_qradar(self):
        """Initialize IBM QRadar client"""
        qradar_config = self.config.get('qradar', {})
        self.qradar_host = qradar_config.get('host', '')
        self.qradar_token = qradar_config.get('token', '')
        self.qradar_version = qradar_config.get('version', '14.0')

    def _init_webhook(self):
        """Initialize generic webhook client"""
        self.webhook_url = self.config.get('webhook_url', '')
        self.webhook_headers = self.config.get('webhook_headers', {})
        self.webhook_auth = self.config.get('webhook_auth', {})

    async def send_alert(self, security_event: SecurityEvent) -> bool:
        """Send security event to configured SIEM"""
        if not self.enabled:
            return True
        
        # Check severity threshold
        if not self._meets_severity_threshold(security_event.severity):
            self.logger.debug(f"Event {security_event.event_id} below severity threshold")
            return True
        
        try:
            if self.siem_type == 'splunk':
                return await self._send_to_splunk(security_event)
            elif self.siem_type == 'elasticsearch':
                return await self._send_to_elasticsearch(security_event)
            elif self.siem_type == 'sentinel':
                return await self._send_to_sentinel(security_event)
            elif self.siem_type == 'qradar':
                return await self._send_to_qradar(security_event)
            elif self.siem_type == 'webhook':
                return await self._send_to_webhook(security_event)
            else:
                self.logger.error(f"Unsupported SIEM type: {self.siem_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send alert to SIEM: {e}")
            return False

    def _meets_severity_threshold(self, severity: SeverityLevel) -> bool:
        """Check if event severity meets configured threshold"""
        severity_order = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        
        return severity_order[severity] >= severity_order[self.severity_threshold]

    async def _send_to_splunk(self, event: SecurityEvent) -> bool:
        """Send event to Splunk HEC"""
        try:
            if not hasattr(self, 'splunk_handler'):
                return False
            
            splunk_event = {
                'time': event.timestamp.timestamp(),
                'host': event.target,
                'source': 'dast-monitor',
                'sourcetype': 'security:scan',
                'index': self.splunk_index,
                'event': {
                    'event_id': event.event_id,
                    'event_type': event.event_type.value,
                    'severity': event.severity.value,
                    'title': event.title,
                    'description': event.description,
                    'target': event.target,
                    'source_system': event.source,
                    'raw_data': event.raw_data,
                    'remediation': event.remediation,
                    'cve_references': event.cve_references or [],
                    'mitre_tactics': event.mitre_tactics or [],
                    'confidence_score': event.confidence_score,
                    'false_positive_likelihood': event.false_positive_likelihood
                }
            }
            
            # Send to Splunk
            url = f"https://{self.splunk_host}:{self.splunk_port}/services/collector"
            headers = {
                'Authorization': f'Splunk {self.splunk_token}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=splunk_event, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        self.logger.info(f"Event {event.event_id} sent to Splunk successfully")
                        return True
                    else:
                        self.logger.error(f"Failed to send to Splunk: {response.status} - {await response.text()}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Splunk integration error: {e}")
            return False

    async def _send_to_elasticsearch(self, event: SecurityEvent) -> bool:
        """Send event to Elasticsearch"""
        try:
            doc = {
                '@timestamp': event.timestamp.isoformat(),
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'severity': event.severity.value,
                'source': event.source,
                'target': event.target,
                'title': event.title,
                'description': event.description,
                'raw_data': event.raw_data,
                'remediation': event.remediation,
                'cve_references': event.cve_references or [],
                'mitre_tactics': event.mitre_tactics or [],
                'confidence_score': event.confidence_score,
                'false_positive_likelihood': event.false_positive_likelihood,
                'labels': {
                    'system': 'dast-monitor',
                    'category': 'security',
                    'subcategory': 'vulnerability_scan'
                }
            }
            
            # Generate document ID
            doc_id = f"{event.event_id}_{int(event.timestamp.timestamp())}"
            
            result = await self.es_client.index(
                index=f"{self.es_index}-{datetime.now().strftime('%Y.%m')}",
                id=doc_id,
                document=doc
            )
            
            if result.get('result') in ['created', 'updated']:
                self.logger.info(f"Event {event.event_id} sent to Elasticsearch successfully")
                return True
            else:
                self.logger.error(f"Failed to send to Elasticsearch: {result}")
                return False
                
        except Exception as e:
            self.logger.error(f"Elasticsearch integration error: {e}")
            return False

    async def _send_to_sentinel(self, event: SecurityEvent) -> bool:
        """Send event to Azure Sentinel"""
        try:
            if not self.sentinel_workspace_id or not self.sentinel_shared_key:
                self.logger.error("Azure Sentinel credentials not configured")
                return False
            
            # Prepare log data
            log_data = [{
                'TimeGenerated': event.timestamp.isoformat(),
                'EventId': event.event_id,
                'EventType': event.event_type.value,
                'Severity': event.severity.value,
                'Source': event.source,
                'Target': event.target,
                'Title': event.title,
                'Description': event.description,
                'RawData': json.dumps(event.raw_data),
                'Remediation': event.remediation or '',
                'CVEReferences': json.dumps(event.cve_references or []),
                'MitreTactics': json.dumps(event.mitre_tactics or []),
                'ConfidenceScore': event.confidence_score,
                'FalsePositiveLikelihood': event.false_positive_likelihood
            }]
            
            # Build signature for authentication
            json_data = json.dumps(log_data)
            body = json_data.encode('utf-8')
            
            # Create authorization signature
            method = 'POST'
            content_type = 'application/json'
            resource = '/api/logs'
            rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            content_length = len(body)
            
            string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{rfc1123date}\n{resource}"
            bytes_to_hash = string_to_hash.encode('utf-8')
            decoded_key = base64.b64decode(self.sentinel_shared_key)
            encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
            authorization = f"SharedKey {self.sentinel_workspace_id}:{encoded_hash}"
            
            # Send to Azure Sentinel
            url = f"https://{self.sentinel_workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            headers = {
                'Authorization': authorization,
                'Content-Type': 'application/json',
                'Log-Type': self.sentinel_log_type,
                'x-ms-date': rfc1123date
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=body, headers=headers) as response:
                    if response.status == 200:
                        self.logger.info(f"Event {event.event_id} sent to Azure Sentinel successfully")
                        return True
                    else:
                        self.logger.error(f"Failed to send to Azure Sentinel: {response.status} - {await response.text()}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Azure Sentinel integration error: {e}")
            return False

    async def _send_to_qradar(self, event: SecurityEvent) -> bool:
        """Send event to IBM QRadar"""
        try:
            if not self.qradar_host or not self.qradar_token:
                self.logger.error("QRadar credentials not configured")
                return False
            
            # Create QRadar event
            qradar_event = {
                'events': [{
                    'timestamp': int(event.timestamp.timestamp() * 1000),
                    'eventname': event.title,
                    'severity': self._map_severity_to_qradar(event.severity),
                    'sourceip': event.target,
                    'destinationip': event.target,
                    'category': 'Security Vulnerability',
                    'properties': [
                        {'name': 'EventId', 'value': event.event_id},
                        {'name': 'EventType', 'value': event.event_type.value},
                        {'name': 'Source', 'value': event.source},
                        {'name': 'Target', 'value': event.target},
                        {'name': 'Description', 'value': event.description},
                        {'name': 'Remediation', 'value': event.remediation or ''},
                        {'name': 'ConfidenceScore', 'value': str(event.confidence_score)},
                        {'name': 'CVEReferences', 'value': ','.join(event.cve_references or [])},
                        {'name': 'MitreTactics', 'value': ','.join(event.mitre_tactics or [])}
                    ]
                }]
            }
            
            url = f"https://{self.qradar_host}/api/siem/events"
            headers = {
                'SEC': self.qradar_token,
                'Content-Type': 'application/json',
                'Version': self.qradar_version
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=qradar_event, headers=headers, ssl=False) as response:
                    if response.status in [200, 201]:
                        self.logger.info(f"Event {event.event_id} sent to QRadar successfully")
                        return True
                    else:
                        self.logger.error(f"Failed to send to QRadar: {response.status} - {await response.text()}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"QRadar integration error: {e}")
            return False

    async def _send_to_webhook(self, event: SecurityEvent) -> bool:
        """Send event to generic webhook"""
        try:
            if not self.webhook_url:
                self.logger.error("Webhook URL not configured")
                return False
            
            payload = {
                'timestamp': event.timestamp.isoformat(),
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'severity': event.severity.value,
                'source': event.source,
                'target': event.target,
                'title': event.title,
                'description': event.description,
                'raw_data': event.raw_data,
                'remediation': event.remediation,
                'cve_references': event.cve_references or [],
                'mitre_tactics': event.mitre_tactics or [],
                'confidence_score': event.confidence_score,
                'false_positive_likelihood': event.false_positive_likelihood,
                'system': 'dast-monitor'
            }
            
            headers = {'Content-Type': 'application/json'}
            headers.update(self.webhook_headers)
            
            # Add authentication if configured
            if self.webhook_auth.get('type') == 'bearer':
                headers['Authorization'] = f"Bearer {self.webhook_auth.get('token')}"
            elif self.webhook_auth.get('type') == 'basic':
                import base64
                credentials = base64.b64encode(f"{self.webhook_auth.get('username')}:{self.webhook_auth.get('password')}".encode()).decode()
                headers['Authorization'] = f"Basic {credentials}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload, headers=headers) as response:
                    if 200 <= response.status < 300:
                        self.logger.info(f"Event {event.event_id} sent to webhook successfully")
                        return True
                    else:
                        self.logger.error(f"Failed to send to webhook: {response.status} - {await response.text()}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Webhook integration error: {e}")
            return False

    def _map_severity_to_qradar(self, severity: SeverityLevel) -> int:
        """Map severity levels to QRadar severity scale (1-10)"""
        mapping = {
            SeverityLevel.INFO: 2,
            SeverityLevel.LOW: 4,
            SeverityLevel.MEDIUM: 6,
            SeverityLevel.HIGH: 8,
            SeverityLevel.CRITICAL: 10
        }
        return mapping.get(severity, 5)

    def create_security_event_from_scan(self, scan_result) -> SecurityEvent:
        """Create security event from scan result"""
        event_id = f"dast_{scan_result.target}_{int(scan_result.timestamp.timestamp())}"
        
        # Determine severity based on alert counts
        if scan_result.alerts_high > 0:
            severity = SeverityLevel.HIGH if scan_result.alerts_high < 5 else SeverityLevel.CRITICAL
            event_type = AlertType.HIGH_RISK_FINDING
        elif scan_result.alerts_medium > 0:
            severity = SeverityLevel.MEDIUM
            event_type = AlertType.VULNERABILITY_DETECTED
        elif scan_result.alerts_low > 0:
            severity = SeverityLevel.LOW
            event_type = AlertType.VULNERABILITY_DETECTED
        else:
            severity = SeverityLevel.INFO
            event_type = AlertType.SCAN_COMPLETED
        
        # Create description
        description = f"DAST scan completed for {scan_result.target}. "
        description += f"Found {scan_result.total_alerts} total alerts: "
        description += f"{scan_result.alerts_high} high, {scan_result.alerts_medium} medium, "
        description += f"{scan_result.alerts_low} low, {scan_result.alerts_info} informational."
        
        # Generate title
        if scan_result.alerts_high > 0:
            title = f"Critical Vulnerabilities Detected - {scan_result.target}"
        elif scan_result.alerts_medium > 0:
            title = f"Security Issues Found - {scan_result.target}"
        else:
            title = f"DAST Scan Completed - {scan_result.target}"
        
        return SecurityEvent(
            event_id=event_id,
            timestamp=scan_result.timestamp,
            event_type=event_type,
            severity=severity,
            source="dast-monitor",
            target=scan_result.target,
            title=title,
            description=description,
            raw_data={
                'scan_type': scan_result.scan_type,
                'duration': scan_result.duration,
                'alerts_high': scan_result.alerts_high,
                'alerts_medium': scan_result.alerts_medium,
                'alerts_low': scan_result.alerts_low,
                'alerts_info': scan_result.alerts_info,
                'status': scan_result.status,
                'report_path': scan_result.report_path,
                'error_message': scan_result.error_message
            },
            remediation=self._generate_remediation_advice(scan_result),
            confidence_score=0.9 if scan_result.status == 'completed' else 0.5
        )

    def _generate_remediation_advice(self, scan_result) -> str:
        """Generate remediation advice based on scan results"""
        advice = []
        
        if scan_result.alerts_high > 0:
            advice.append("🔴 URGENT: Address high-severity vulnerabilities immediately")
            advice.append("- Review detailed scan report for specific remediation steps")
            advice.append("- Implement security patches and configuration fixes")
            advice.append("- Consider taking affected systems offline if actively exploitable")
        
        if scan_result.alerts_medium > 0:
            advice.append("🟡 MEDIUM: Schedule remediation for medium-severity issues")
            advice.append("- Prioritize based on asset criticality and exposure")
            advice.append("- Implement defense-in-depth controls")
        
        if scan_result.alerts_low > 0:
            advice.append("🔵 LOW: Address low-severity issues during maintenance windows")
            advice.append("- Include in regular security hardening activities")
        
        advice.append("📊 Next steps:")
        advice.append("- Review full scan report for detailed findings")
        advice.append("- Verify fixes with follow-up scans")
        advice.append("- Update security documentation and runbooks")
        
        return "\n".join(advice)

    async def send_test_event(self) -> bool:
        """Send a test event to verify SIEM integration"""
        test_event = SecurityEvent(
            event_id="test_" + str(int(time.time())),
            timestamp=datetime.now(timezone.utc),
            event_type=AlertType.SCAN_COMPLETED,
            severity=SeverityLevel.INFO,
            source="dast-monitor",
            target="test.example.com",
            title="DAST Monitor Test Event",
            description="This is a test event to verify SIEM integration",
            raw_data={"test": True, "integration_check": "success"},
            remediation="No action required - this was a test event"
        )
        
        return await self.send_alert(test_event)

    def cleanup(self):
        """Cleanup SIEM integration resources"""
        if hasattr(self, 'es_client'):
            asyncio.create_task(self.es_client.close())

async def main():
    """Test SIEM integration"""
    config = {
        'enabled': True,
        'type': 'webhook',
        'webhook_url': 'https://httpbin.org/post',
        'severity_threshold': 'low'
    }
    
    siem = SIEMIntegration(config)
    
    # Send test event
    success = await siem.send_test_event()
    if success:
        print("✓ SIEM test event sent successfully")
    else:
        print("✗ SIEM test event failed")
    
    siem.cleanup()

if __name__ == '__main__':
    asyncio.run(main())