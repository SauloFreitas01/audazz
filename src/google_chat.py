import requests
import json
import logging
from typing import Dict, Any, Optional


logger = logging.getLogger(__name__)


class GoogleChatNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_scan_notification(self, summary_report: Dict[str, Any]) -> bool:
        """Send scan results notification to Google Chat."""
        if not self.webhook_url:
            logger.warning("Google Chat webhook URL not configured")
            return False

        try:
            message = self._create_scan_message(summary_report)
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            if response.status_code == 200:
                logger.info(f"Notification sent successfully for {summary_report['target']}")
                return True
            else:
                logger.error(f"Failed to send notification: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending Google Chat notification: {e}")
            return False

    def _create_scan_message(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Create Google Chat message from scan summary."""
        target = summary['target']
        severity = summary['severity']
        total_vulns = summary['total_vulnerabilities']
        breakdown = summary['breakdown']
        timestamp = summary['scan_timestamp']

        # Create header section
        header = {
            "header": {
                "title": f"🔍 AutoDast Security Scan Report",
                "subtitle": f"Target: {target}",
                "imageUrl": "https://owasp.org/assets/images/logo.png"
            }
        }

        # Create widgets list
        widgets = []

        # Add summary widget
        summary_widget = {
            "keyValue": {
                "topLabel": "Scan Summary",
                "content": f"{severity} - {total_vulns} vulnerabilities found",
                "contentMultiline": False,
                "icon": "SECURITY"
            }
        }
        widgets.append(summary_widget)

        # Add breakdown widget if vulnerabilities found
        if total_vulns > 0:
            breakdown_text = []
            if breakdown['high'] > 0:
                breakdown_text.append(f"🔴 High: {breakdown['high']}")
            if breakdown['medium'] > 0:
                breakdown_text.append(f"🟡 Medium: {breakdown['medium']}")
            if breakdown['low'] > 0:
                breakdown_text.append(f"🟢 Low: {breakdown['low']}")
            if breakdown['informational'] > 0:
                breakdown_text.append(f"ℹ️ Info: {breakdown['informational']}")

            breakdown_widget = {
                "keyValue": {
                    "topLabel": "Vulnerability Breakdown",
                    "content": " | ".join(breakdown_text),
                    "contentMultiline": True,
                    "icon": "DESCRIPTION"
                }
            }
            widgets.append(breakdown_widget)

        # Add top vulnerabilities if available
        top_vulns = summary.get('top_vulnerabilities', [])
        if top_vulns:
            vulns_text = []
            for vuln in top_vulns[:3]:  # Show top 3
                risk_emoji = "🔴" if vuln['risk'] == 'High' else "🟡"
                vulns_text.append(f"{risk_emoji} {vuln['name']}")

            vulns_widget = {
                "keyValue": {
                    "topLabel": "Top Vulnerabilities",
                    "content": "\n".join(vulns_text),
                    "contentMultiline": True,
                    "icon": "WARNING"
                }
            }
            widgets.append(vulns_widget)

        # Add timestamp widget
        time_widget = {
            "keyValue": {
                "topLabel": "Scan Completed",
                "content": timestamp,
                "contentMultiline": False,
                "icon": "CLOCK"
            }
        }
        widgets.append(time_widget)

        # Create the card
        card = {
            "cards": [
                {
                    **header,
                    "sections": [
                        {
                            "widgets": widgets
                        }
                    ]
                }
            ]
        }

        return card

    def send_error_notification(self, target: str, error_message: str) -> bool:
        """Send error notification to Google Chat."""
        if not self.webhook_url:
            return False

        try:
            message = {
                "cards": [
                    {
                        "header": {
                            "title": "⚠️ AutoDast Scan Error",
                            "subtitle": f"Target: {target}",
                        },
                        "sections": [
                            {
                                "widgets": [
                                    {
                                        "keyValue": {
                                            "topLabel": "Error Details",
                                            "content": error_message,
                                            "contentMultiline": True,
                                            "icon": "WARNING"
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }

            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Error sending error notification: {e}")
            return False

    def send_status_notification(self, message: str, details: Optional[Dict[str, Any]] = None) -> bool:
        """Send general status notification to Google Chat."""
        if not self.webhook_url:
            return False

        try:
            widgets = [
                {
                    "keyValue": {
                        "topLabel": "Status Update",
                        "content": message,
                        "contentMultiline": True,
                        "icon": "DESCRIPTION"
                    }
                }
            ]

            if details:
                for key, value in details.items():
                    widgets.append({
                        "keyValue": {
                            "topLabel": key,
                            "content": str(value),
                            "contentMultiline": False
                        }
                    })

            chat_message = {
                "cards": [
                    {
                        "header": {
                            "title": "📊 AutoDast Status",
                        },
                        "sections": [
                            {
                                "widgets": widgets
                            }
                        ]
                    }
                ]
            }

            response = requests.post(
                self.webhook_url,
                json=chat_message,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Error sending status notification: {e}")
            return False

    def test_webhook(self) -> bool:
        """Test the Google Chat webhook connection."""
        if not self.webhook_url:
            return False

        test_message = {
            "text": "🧪 AutoDast webhook test - Connection successful!"
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=test_message,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Webhook test failed: {e}")
            return False