#!/usr/bin/env python3
"""
Google Chat Integration Module
Handles notifications and alerts to Google Chat spaces via webhooks
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

import aiohttp
import requests


class MessageStyle(Enum):
    SIMPLE = "simple"
    CARD = "card"
    RICH = "rich"


class SeverityColor(Enum):
    CRITICAL = "#D93025"  # Red
    HIGH = "#EA4335"      # Dark Red
    MEDIUM = "#FBBC04"    # Yellow
    LOW = "#34A853"       # Green
    INFO = "#4285F4"      # Blue


@dataclass
class GoogleChatMessage:
    text: str
    title: Optional[str] = None
    subtitle: Optional[str] = None
    cards: Optional[List[Dict]] = None
    thread_key: Optional[str] = None
    style: MessageStyle = MessageStyle.SIMPLE


class GoogleChatIntegration:
    """Google Chat webhook integration for DAST monitoring alerts"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get('enabled', False)
        
        if not self.enabled:
            self.logger.info("Google Chat integration disabled")
            return
        
        self.webhook_url = config.get('webhook_url', '')
        self.space_name = config.get('space_name', 'DAST Security Monitoring')
        self.bot_name = config.get('bot_name', 'DAST Monitor')
        self.severity_threshold = config.get('severity_threshold', 'medium')
        self.message_style = MessageStyle(config.get('message_style', 'card'))
        self.thread_alerts = config.get('thread_alerts', True)
        
        if not self.webhook_url:
            self.logger.error("Google Chat webhook URL not configured")
            self.enabled = False

    async def send_scan_alert(self, scan_result, additional_context: Optional[Dict] = None) -> bool:
        """Send scan completion alert to Google Chat"""
        if not self.enabled:
            return True
        
        try:
            severity = self._determine_severity(scan_result)
            
            if not self._meets_severity_threshold(severity):
                self.logger.debug(f"Scan result for {scan_result.target} below severity threshold")
                return True
            
            message = self._create_scan_message(scan_result, additional_context)
            return await self._send_message(message)
            
        except Exception as e:
            self.logger.error(f"Failed to send Google Chat alert: {e}")
            return False

    async def send_discovery_alert(self, domain: str, new_subdomains: List[str], 
                                 total_subdomains: int) -> bool:
        """Send subdomain discovery alert"""
        if not self.enabled or not new_subdomains:
            return True
        
        try:
            message = self._create_discovery_message(domain, new_subdomains, total_subdomains)
            return await self._send_message(message)
            
        except Exception as e:
            self.logger.error(f"Failed to send Google Chat discovery alert: {e}")
            return False

    async def send_system_alert(self, alert_type: str, message: str, 
                              severity: str = "medium", details: Optional[Dict] = None) -> bool:
        """Send system-level alerts (failures, errors, etc.)"""
        if not self.enabled:
            return True
        
        try:
            chat_message = self._create_system_message(alert_type, message, severity, details)
            return await self._send_message(chat_message)
            
        except Exception as e:
            self.logger.error(f"Failed to send Google Chat system alert: {e}")
            return False

    def _create_scan_message(self, scan_result, additional_context: Optional[Dict] = None) -> GoogleChatMessage:
        """Create formatted message for scan results"""
        severity = self._determine_severity(scan_result)
        color = SeverityColor[severity.upper()].value
        
        if self.message_style == MessageStyle.SIMPLE:
            return self._create_simple_scan_message(scan_result, severity)
        else:
            return self._create_card_scan_message(scan_result, severity, color, additional_context)

    def _create_simple_scan_message(self, scan_result, severity: str) -> GoogleChatMessage:
        """Create simple text message"""
        status_emoji = "✅" if scan_result.status == 'completed' else "❌"
        severity_emoji = self._get_severity_emoji(severity)
        
        text = f"{status_emoji} *DAST Scan {scan_result.status.title()}*\n\n"
        text += f"🎯 *Target:* {scan_result.target}\n"
        text += f"📊 *Scan Type:* {scan_result.scan_type.title()}\n"
        text += f"⏱️ *Duration:* {int(scan_result.duration)}s\n"
        text += f"{severity_emoji} *Severity:* {severity.title()}\n\n"
        
        text += f"🚨 *Alerts Found:*\n"
        text += f"  • High: {scan_result.alerts_high}\n"
        text += f"  • Medium: {scan_result.alerts_medium}\n"
        text += f"  • Low: {scan_result.alerts_low}\n"
        text += f"  • Info: {scan_result.alerts_info}\n"
        text += f"  • **Total: {scan_result.total_alerts}**\n"
        
        if scan_result.status != 'completed':
            text += f"\n⚠️ *Error:* {scan_result.error_message or 'Unknown error'}"
        
        text += f"\n📅 *Timestamp:* {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        
        return GoogleChatMessage(
            text=text,
            thread_key=f"scan_{scan_result.target}" if self.thread_alerts else None
        )

    def _create_card_scan_message(self, scan_result, severity: str, color: str, 
                                additional_context: Optional[Dict] = None) -> GoogleChatMessage:
        """Create rich card message"""
        status_emoji = "✅" if scan_result.status == 'completed' else "❌"
        severity_emoji = self._get_severity_emoji(severity)
        
        # Header
        header = {
            "title": f"{status_emoji} DAST Scan {scan_result.status.title()}",
            "subtitle": f"Target: {scan_result.target}",
            "imageUrl": "https://owasp.org/assets/images/logo.png",
            "imageStyle": "AVATAR"
        }
        
        # Scan details section
        scan_details = {
            "header": f"📊 Scan Details",
            "widgets": [
                {
                    "keyValue": {
                        "topLabel": "Target",
                        "content": scan_result.target,
                        "icon": "BOOKMARK"
                    }
                },
                {
                    "keyValue": {
                        "topLabel": "Scan Type",
                        "content": scan_result.scan_type.title(),
                        "icon": "DESCRIPTION"
                    }
                },
                {
                    "keyValue": {
                        "topLabel": "Duration",
                        "content": f"{int(scan_result.duration)}s",
                        "icon": "CLOCK"
                    }
                },
                {
                    "keyValue": {
                        "topLabel": "Status",
                        "content": f"{severity_emoji} {severity.title()}",
                        "icon": "STAR"
                    }
                }
            ]
        }
        
        # Alerts summary section
        alert_widgets = [
            {
                "keyValue": {
                    "topLabel": "🔴 High",
                    "content": str(scan_result.alerts_high),
                    "contentMultiline": False
                }
            },
            {
                "keyValue": {
                    "topLabel": "🟡 Medium", 
                    "content": str(scan_result.alerts_medium),
                    "contentMultiline": False
                }
            },
            {
                "keyValue": {
                    "topLabel": "🔵 Low",
                    "content": str(scan_result.alerts_low),
                    "contentMultiline": False
                }
            },
            {
                "keyValue": {
                    "topLabel": "ℹ️ Info",
                    "content": str(scan_result.alerts_info),
                    "contentMultiline": False
                }
            }
        ]
        
        alerts_section = {
            "header": f"🚨 Security Alerts (Total: {scan_result.total_alerts})",
            "widgets": alert_widgets
        }
        
        # Actions section
        actions = []
        if scan_result.report_path:
            actions.append({
                "textButton": {
                    "text": "📄 View Report",
                    "onClick": {
                        "openLink": {
                            "url": f"file://{scan_result.report_path}"
                        }
                    }
                }
            })
        
        actions_section = {
            "widgets": [
                {
                    "buttons": actions
                }
            ]
        } if actions else None
        
        # Error section (if applicable)
        error_section = None
        if scan_result.status != 'completed' and scan_result.error_message:
            error_section = {
                "header": "⚠️ Error Details",
                "widgets": [
                    {
                        "textParagraph": {
                            "text": f"<font color='#D93025'>{scan_result.error_message}</font>"
                        }
                    }
                ]
            }
        
        # Build card sections
        sections = [scan_details, alerts_section]
        if error_section:
            sections.append(error_section)
        if actions_section:
            sections.append(actions_section)
        
        # Additional context section
        if additional_context:
            context_widgets = []
            for key, value in additional_context.items():
                context_widgets.append({
                    "keyValue": {
                        "topLabel": key,
                        "content": str(value)
                    }
                })
            
            if context_widgets:
                sections.append({
                    "header": "📋 Additional Information",
                    "widgets": context_widgets
                })
        
        card = {
            "header": header,
            "sections": sections
        }
        
        return GoogleChatMessage(
            text=f"DAST scan completed for {scan_result.target}",
            cards=[card],
            thread_key=f"scan_{scan_result.target}" if self.thread_alerts else None
        )

    def _create_discovery_message(self, domain: str, new_subdomains: List[str], 
                                total_subdomains: int) -> GoogleChatMessage:
        """Create message for subdomain discovery"""
        if self.message_style == MessageStyle.SIMPLE:
            text = f"🔍 *New Subdomains Discovered*\n\n"
            text += f"🎯 *Domain:* {domain}\n"
            text += f"📊 *New Subdomains:* {len(new_subdomains)}\n"
            text += f"📈 *Total Subdomains:* {total_subdomains}\n\n"
            
            if len(new_subdomains) <= 10:
                text += "🆕 *Discovered:*\n"
                for subdomain in new_subdomains:
                    text += f"  • {subdomain}\n"
            else:
                text += f"🆕 *Sample Discoveries:*\n"
                for subdomain in new_subdomains[:10]:
                    text += f"  • {subdomain}\n"
                text += f"  ... and {len(new_subdomains) - 10} more\n"
            
            return GoogleChatMessage(
                text=text,
                thread_key=f"discovery_{domain}" if self.thread_alerts else None
            )
        
        else:
            # Card format for discovery
            header = {
                "title": "🔍 New Subdomains Discovered",
                "subtitle": f"Domain: {domain}",
                "imageUrl": "https://cdn-icons-png.flaticon.com/512/1067/1067566.png",
                "imageStyle": "AVATAR"
            }
            
            summary_section = {
                "header": "📊 Discovery Summary",
                "widgets": [
                    {
                        "keyValue": {
                            "topLabel": "Target Domain",
                            "content": domain,
                            "icon": "BOOKMARK"
                        }
                    },
                    {
                        "keyValue": {
                            "topLabel": "New Subdomains",
                            "content": str(len(new_subdomains)),
                            "icon": "STAR"
                        }
                    },
                    {
                        "keyValue": {
                            "topLabel": "Total Subdomains",
                            "content": str(total_subdomains),
                            "icon": "DESCRIPTION"
                        }
                    }
                ]
            }
            
            # Subdomain list section
            subdomain_text = "\n".join([f"• {sub}" for sub in new_subdomains[:15]])
            if len(new_subdomains) > 15:
                subdomain_text += f"\n... and {len(new_subdomains) - 15} more"
            
            subdomains_section = {
                "header": "🆕 Discovered Subdomains",
                "widgets": [
                    {
                        "textParagraph": {
                            "text": subdomain_text
                        }
                    }
                ]
            }
            
            card = {
                "header": header,
                "sections": [summary_section, subdomains_section]
            }
            
            return GoogleChatMessage(
                text=f"Discovered {len(new_subdomains)} new subdomains for {domain}",
                cards=[card],
                thread_key=f"discovery_{domain}" if self.thread_alerts else None
            )

    def _create_system_message(self, alert_type: str, message: str, 
                             severity: str, details: Optional[Dict] = None) -> GoogleChatMessage:
        """Create system alert message"""
        severity_emoji = self._get_severity_emoji(severity)
        color = SeverityColor[severity.upper()].value
        
        if self.message_style == MessageStyle.SIMPLE:
            text = f"{severity_emoji} *DAST Monitor System Alert*\n\n"
            text += f"🚨 *Alert Type:* {alert_type}\n"
            text += f"📝 *Message:* {message}\n"
            text += f"⚠️ *Severity:* {severity.title()}\n"
            
            if details:
                text += f"\n📋 *Details:*\n"
                for key, value in details.items():
                    text += f"  • {key}: {value}\n"
            
            text += f"\n📅 *Timestamp:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
            
            return GoogleChatMessage(text=text)
        
        else:
            # Card format for system alerts
            header = {
                "title": f"{severity_emoji} System Alert",
                "subtitle": alert_type,
                "imageUrl": "https://cdn-icons-png.flaticon.com/512/564/564619.png",
                "imageStyle": "AVATAR"
            }
            
            alert_section = {
                "widgets": [
                    {
                        "keyValue": {
                            "topLabel": "Alert Type",
                            "content": alert_type,
                            "icon": "STAR"
                        }
                    },
                    {
                        "textParagraph": {
                            "text": f"<font color='{color}'><b>{message}</b></font>"
                        }
                    }
                ]
            }
            
            sections = [alert_section]
            
            if details:
                detail_widgets = []
                for key, value in details.items():
                    detail_widgets.append({
                        "keyValue": {
                            "topLabel": key,
                            "content": str(value)
                        }
                    })
                
                sections.append({
                    "header": "📋 Additional Details",
                    "widgets": detail_widgets
                })
            
            card = {
                "header": header,
                "sections": sections
            }
            
            return GoogleChatMessage(
                text=f"System alert: {alert_type}",
                cards=[card]
            )

    async def _send_message(self, message: GoogleChatMessage) -> bool:
        """Send message to Google Chat webhook"""
        try:
            payload = self._build_webhook_payload(message)
            
            async with aiohttp.ClientSession() as session:
                params = {}
                if message.thread_key:
                    params['threadKey'] = message.thread_key
                
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    params=params,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                ) as response:
                    if response.status == 200:
                        self.logger.info("Google Chat message sent successfully")
                        return True
                    else:
                        response_text = await response.text()
                        self.logger.error(f"Failed to send Google Chat message: {response.status} - {response_text}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending Google Chat message: {e}")
            return False

    def _build_webhook_payload(self, message: GoogleChatMessage) -> Dict:
        """Build Google Chat webhook payload"""
        if message.cards:
            # Card-based message
            payload = {
                "text": message.text,
                "cards": message.cards
            }
        else:
            # Simple text message
            payload = {
                "text": message.text
            }
        
        return payload

    def _determine_severity(self, scan_result) -> str:
        """Determine alert severity based on scan results"""
        if scan_result.status != 'completed':
            return 'high'  # Failed scans are high priority
        elif scan_result.alerts_high > 0:
            return 'critical' if scan_result.alerts_high >= 5 else 'high'
        elif scan_result.alerts_medium > 0:
            return 'medium'
        elif scan_result.alerts_low > 0:
            return 'low'
        else:
            return 'info'

    def _meets_severity_threshold(self, severity: str) -> bool:
        """Check if severity meets configured threshold"""
        severity_levels = {
            'info': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        threshold_level = severity_levels.get(self.severity_threshold, 2)
        alert_level = severity_levels.get(severity, 0)
        
        return alert_level >= threshold_level

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }
        return emojis.get(severity, 'ℹ️')

    async def send_test_message(self) -> bool:
        """Send test message to verify integration"""
        if not self.enabled:
            return False
        
        test_message = GoogleChatMessage(
            text="🧪 **DAST Monitor Test Message**\n\nThis is a test message to verify Google Chat integration is working correctly.",
            title="Test Notification"
        )
        
        result = await self._send_message(test_message)
        if result:
            self.logger.info("Google Chat test message sent successfully")
        else:
            self.logger.error("Failed to send Google Chat test message")
        
        return result

    def get_webhook_url_info(self) -> Dict[str, Any]:
        """Get information about the configured webhook URL"""
        if not self.webhook_url:
            return {"status": "not_configured"}
        
        # Extract space ID from webhook URL if possible
        try:
            # Google Chat webhook URLs follow pattern:
            # https://chat.googleapis.com/v1/spaces/SPACE_ID/messages?key=KEY&token=TOKEN
            if "chat.googleapis.com" in self.webhook_url and "/spaces/" in self.webhook_url:
                space_part = self.webhook_url.split("/spaces/")[1].split("/")[0]
                return {
                    "status": "configured",
                    "space_id": space_part,
                    "webhook_configured": True
                }
            else:
                return {
                    "status": "configured",
                    "webhook_configured": True,
                    "custom_webhook": True
                }
        except:
            return {
                "status": "configured",
                "webhook_configured": True
            }


async def main():
    """Test Google Chat integration"""
    # Test configuration
    config = {
        'enabled': True,
        'webhook_url': 'https://chat.googleapis.com/v1/spaces/YOUR_SPACE/messages?key=YOUR_KEY&token=YOUR_TOKEN',
        'space_name': 'Security Alerts',
        'bot_name': 'DAST Monitor',
        'severity_threshold': 'low',
        'message_style': 'card',
        'thread_alerts': True
    }
    
    google_chat = GoogleChatIntegration(config)
    
    if google_chat.enabled:
        # Send test message
        success = await google_chat.send_test_message()
        if success:
            print("✅ Google Chat integration test successful")
        else:
            print("❌ Google Chat integration test failed")
    else:
        print("⚠️ Google Chat integration is disabled")


if __name__ == '__main__':
    asyncio.run(main())