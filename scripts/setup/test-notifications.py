#!/usr/bin/env python3
"""
Notification Integration Test Script
Tests Slack and Google Chat webhook integrations
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Dict, Any

import aiohttp
import requests
import yaml

# Add app path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from integrations.google_chat_integration import GoogleChatIntegration
from core.dast_monitor import ScanResult


class NotificationTester:
    """Test notification integrations"""
    
    def __init__(self, config_path: str = "config/dast_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Load environment variables
            for key, value in os.environ.items():
                if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                    env_var = value[2:-1]
                    if env_var in os.environ:
                        # This is a simplified replacement - in real usage, 
                        # you'd want proper template substitution
                        pass
            
            return config
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def create_test_scan_result(self, scenario: str = "success") -> ScanResult:
        """Create a test scan result for testing"""
        base_result = ScanResult(
            target="test.example.com",
            timestamp=datetime.now(),
            scan_type="standard",
            duration=120.5,
            alerts_high=0,
            alerts_medium=0,
            alerts_low=0,
            alerts_info=0,
            total_alerts=0,
            status="completed",
            report_path="/reports/test-scan-report.json"
        )
        
        scenarios = {
            "success": {
                "alerts_high": 0,
                "alerts_medium": 2,
                "alerts_low": 5,
                "alerts_info": 8,
                "total_alerts": 15,
                "status": "completed"
            },
            "critical": {
                "alerts_high": 5,
                "alerts_medium": 8,
                "alerts_low": 12,
                "alerts_info": 15,
                "total_alerts": 40,
                "status": "completed"
            },
            "failed": {
                "alerts_high": 0,
                "alerts_medium": 0,
                "alerts_low": 0,
                "alerts_info": 0,
                "total_alerts": 0,
                "status": "failed",
                "error_message": "Scan timeout - target unreachable"
            }
        }
        
        if scenario in scenarios:
            for key, value in scenarios[scenario].items():
                setattr(base_result, key, value)
        
        return base_result
    
    async def test_google_chat(self) -> bool:
        """Test Google Chat integration"""
        print("🔍 Testing Google Chat Integration...")
        
        google_chat_config = self.config.get('notifications', {}).get('google_chat', {})
        
        if not google_chat_config.get('enabled', False):
            print("⚠️  Google Chat integration is disabled in config")
            return False
        
        if not google_chat_config.get('webhook_url'):
            print("❌ Google Chat webhook URL not configured")
            return False
        
        # Initialize Google Chat integration
        google_chat = GoogleChatIntegration(google_chat_config)
        
        try:
            # Test 1: Simple test message
            print("  📤 Sending test message...")
            test_result = await google_chat.send_test_message()
            
            if test_result:
                print("  ✅ Test message sent successfully")
            else:
                print("  ❌ Failed to send test message")
                return False
            
            # Test 2: Scan completion alert (success scenario)
            print("  📤 Sending successful scan alert...")
            success_scan = self.create_test_scan_result("success")
            scan_result = await google_chat.send_scan_alert(success_scan)
            
            if scan_result:
                print("  ✅ Successful scan alert sent")
            else:
                print("  ❌ Failed to send successful scan alert")
            
            # Test 3: Critical vulnerability alert
            print("  📤 Sending critical vulnerability alert...")
            critical_scan = self.create_test_scan_result("critical")
            critical_result = await google_chat.send_scan_alert(critical_scan)
            
            if critical_result:
                print("  ✅ Critical vulnerability alert sent")
            else:
                print("  ❌ Failed to send critical vulnerability alert")
            
            # Test 4: Failed scan alert
            print("  📤 Sending failed scan alert...")
            failed_scan = self.create_test_scan_result("failed")
            failed_result = await google_chat.send_scan_alert(failed_scan)
            
            if failed_result:
                print("  ✅ Failed scan alert sent")
            else:
                print("  ❌ Failed to send failed scan alert")
            
            # Test 5: Subdomain discovery alert
            print("  📤 Sending subdomain discovery alert...")
            discovery_result = await google_chat.send_discovery_alert(
                domain="test.example.com",
                new_subdomains=["api.test.example.com", "staging.test.example.com", "admin.test.example.com"],
                total_subdomains=15
            )
            
            if discovery_result:
                print("  ✅ Subdomain discovery alert sent")
            else:
                print("  ❌ Failed to send subdomain discovery alert")
            
            print("🎉 Google Chat integration test completed!")
            return True
            
        except Exception as e:
            print(f"  ❌ Error testing Google Chat integration: {e}")
            return False
    
    async def test_slack(self) -> bool:
        """Test Slack integration"""
        print("🔍 Testing Slack Integration...")
        
        slack_config = self.config.get('notifications', {}).get('slack', {})
        
        if not slack_config.get('enabled', False):
            print("⚠️  Slack integration is disabled in config")
            return False
        
        webhook_url = slack_config.get('webhook_url')
        if not webhook_url:
            print("❌ Slack webhook URL not configured")
            return False
        
        try:
            # Test 1: Simple message
            print("  📤 Sending simple test message...")
            simple_payload = {
                "text": "🧪 DAST Monitor Test - Slack Integration Working!"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=simple_payload) as response:
                    if response.status == 200:
                        print("  ✅ Simple test message sent successfully")
                    else:
                        print(f"  ❌ Failed to send simple message: {response.status}")
                        return False
            
            # Test 2: Rich attachment message
            print("  📤 Sending rich attachment message...")
            scan_result = self.create_test_scan_result("success")
            
            rich_payload = {
                "text": f"DAST Scan Completed: {scan_result.target}",
                "attachments": [
                    {
                        "color": "good",
                        "title": "🛡️ Security Scan Results",
                        "fields": [
                            {"title": "Target", "value": scan_result.target, "short": True},
                            {"title": "Status", "value": scan_result.status.title(), "short": True},
                            {"title": "High Alerts", "value": str(scan_result.alerts_high), "short": True},
                            {"title": "Medium Alerts", "value": str(scan_result.alerts_medium), "short": True},
                            {"title": "Total Alerts", "value": str(scan_result.total_alerts), "short": True},
                            {"title": "Duration", "value": f"{int(scan_result.duration)}s", "short": True}
                        ],
                        "footer": "DAST Monitor",
                        "ts": int(scan_result.timestamp.timestamp())
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=rich_payload) as response:
                    if response.status == 200:
                        print("  ✅ Rich attachment message sent successfully")
                    else:
                        print(f"  ❌ Failed to send rich message: {response.status}")
                        return False
            
            # Test 3: Critical alert
            print("  📤 Sending critical alert message...")
            critical_scan = self.create_test_scan_result("critical")
            
            critical_payload = {
                "text": "🚨 CRITICAL VULNERABILITIES DETECTED!",
                "attachments": [
                    {
                        "color": "danger",
                        "title": f"Critical Security Issues Found - {critical_scan.target}",
                        "text": f"High severity vulnerabilities detected: {critical_scan.alerts_high}",
                        "fields": [
                            {"title": "🔴 High", "value": str(critical_scan.alerts_high), "short": True},
                            {"title": "🟡 Medium", "value": str(critical_scan.alerts_medium), "short": True},
                            {"title": "🔵 Low", "value": str(critical_scan.alerts_low), "short": True},
                            {"title": "ℹ️ Info", "value": str(critical_scan.alerts_info), "short": True}
                        ],
                        "footer": "Immediate Action Required",
                        "ts": int(critical_scan.timestamp.timestamp())
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=critical_payload) as response:
                    if response.status == 200:
                        print("  ✅ Critical alert message sent successfully")
                    else:
                        print(f"  ❌ Failed to send critical alert: {response.status}")
            
            print("🎉 Slack integration test completed!")
            return True
            
        except Exception as e:
            print(f"  ❌ Error testing Slack integration: {e}")
            return False
    
    def test_webhook_connectivity(self, url: str, name: str) -> bool:
        """Test basic webhook connectivity"""
        print(f"🔗 Testing {name} webhook connectivity...")
        
        try:
            response = requests.head(url, timeout=10)
            if response.status_code < 500:  # Any response is good
                print(f"  ✅ {name} webhook is reachable")
                return True
            else:
                print(f"  ⚠️  {name} webhook returned {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"  ❌ {name} webhook is unreachable: {e}")
            return False
    
    async def run_all_tests(self):
        """Run all notification tests"""
        print("🚀 Starting Notification Integration Tests")
        print("=" * 50)
        
        results = {}
        
        # Test webhook connectivity first
        notifications_config = self.config.get('notifications', {})
        
        if notifications_config.get('slack', {}).get('webhook_url'):
            results['slack_connectivity'] = self.test_webhook_connectivity(
                notifications_config['slack']['webhook_url'], 
                "Slack"
            )
        
        if notifications_config.get('google_chat', {}).get('webhook_url'):
            results['google_chat_connectivity'] = self.test_webhook_connectivity(
                notifications_config['google_chat']['webhook_url'], 
                "Google Chat"
            )
        
        print()
        
        # Test integrations
        results['google_chat'] = await self.test_google_chat()
        print()
        results['slack'] = await self.test_slack()
        
        print()
        print("=" * 50)
        print("🏁 Test Results Summary:")
        print("=" * 50)
        
        for test_name, result in results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"  {test_name.replace('_', ' ').title()}: {status}")
        
        passed = sum(1 for r in results.values() if r)
        total = len(results)
        
        print()
        if passed == total:
            print("🎉 All tests passed! Notifications are working correctly.")
        else:
            print(f"⚠️  {passed}/{total} tests passed. Check failed integrations.")
        
        print()
        print("💡 Next Steps:")
        print("  1. Fix any failed integrations")
        print("  2. Check your webhook URLs and credentials")
        print("  3. Verify bot permissions in chat platforms")
        print("  4. Test with real DAST scans")


async def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test notification integrations')
    parser.add_argument('--config', default='config/dast_config.yaml', help='Config file path')
    parser.add_argument('--test', choices=['all', 'slack', 'google-chat'], default='all', help='Which tests to run')
    
    args = parser.parse_args()
    
    tester = NotificationTester(args.config)
    
    if args.test == 'all':
        await tester.run_all_tests()
    elif args.test == 'slack':
        await tester.test_slack()
    elif args.test == 'google-chat':
        await tester.test_google_chat()


if __name__ == '__main__':
    asyncio.run(main())