import requests
import json
import logging
import os
import base64
from typing import Dict, Any, Optional, List
from pathlib import Path


logger = logging.getLogger(__name__)


class GoogleChatNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_scan_notification(self, summary_report: Dict[str, Any], report_files: Optional[Dict[str, str]] = None) -> bool:
        """Send scan results notification to Google Chat with optional report files."""
        if not self.webhook_url:
            logger.warning("Google Chat webhook URL not configured")
            return False

        try:
            message = self._create_scan_message(summary_report, report_files)
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

    def _create_scan_message(self, summary: Dict[str, Any], report_files: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
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

        # Add report files if available
        if report_files:
            report_links = []
            for format_type, file_path in report_files.items():
                if os.path.exists(file_path):
                    filename = os.path.basename(file_path)
                    file_size = self._get_human_readable_size(os.path.getsize(file_path))
                    report_links.append(f"📄 {format_type.upper()}: {filename} ({file_size})")

            if report_links:
                reports_widget = {
                    "keyValue": {
                        "topLabel": "📋 Available Reports",
                        "content": "\n".join(report_links),
                        "contentMultiline": True,
                        "icon": "DESCRIPTION"
                    }
                }
                widgets.append(reports_widget)

                # Add buttons for report download
                buttons = []
                for format_type, file_path in report_files.items():
                    if os.path.exists(file_path):
                        filename = os.path.basename(file_path)
                        buttons.append({
                            "textButton": {
                                "text": f"Download {format_type.upper()} Report",
                                "onClick": {
                                    "openLink": {
                                        "url": f"file://{os.path.abspath(file_path)}"
                                    }
                                }
                            }
                        })

                if buttons:
                    button_widget = {
                        "buttons": buttons
                    }
                    widgets.append(button_widget)

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

    def _get_human_readable_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable size."""
        if size_bytes == 0:
            return "0B"
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024.0 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f}{size_names[i]}"

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

    def send_monthly_report_notification(self, executive_summary: Dict[str, Any], report_files: Optional[Dict[str, str]] = None) -> bool:
        """Send monthly executive report notification to Google Chat with files."""
        if not self.webhook_url:
            logger.warning("Google Chat webhook URL not configured")
            return False

        try:
            message = self._create_monthly_report_message(executive_summary, report_files)
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            if response.status_code == 200:
                logger.info(f"Monthly report notification sent successfully")
                return True
            else:
                logger.error(f"Failed to send monthly report notification: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending monthly report notification: {e}")
            return False

    def _create_monthly_report_message(self, executive_summary: Dict[str, Any], report_files: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Create Google Chat message for monthly executive report."""
        overall_risk = executive_summary['overall_risk']
        total_targets = executive_summary['total_targets']
        vulnerabilities = executive_summary['vulnerabilities']
        scan_month = executive_summary['scan_month']
        risk_emoji = executive_summary['risk_emoji']

        # Create header section
        header = {
            "header": {
                "title": f"📊 Monthly Security Executive Report",
                "subtitle": f"{scan_month} - {risk_emoji} {overall_risk} Risk Level",
                "imageUrl": "https://owasp.org/assets/images/logo.png"
            }
        }

        # Create widgets list
        widgets = []

        # Add executive summary widget
        summary_widget = {
            "keyValue": {
                "topLabel": "Executive Summary",
                "content": f"{total_targets} targets scanned | {vulnerabilities['total']} total vulnerabilities",
                "contentMultiline": False,
                "icon": "SECURITY"
            }
        }
        widgets.append(summary_widget)

        # Add vulnerability breakdown widget
        breakdown_text = []
        if vulnerabilities['critical'] > 0:
            breakdown_text.append(f"🔴 Critical: {vulnerabilities['critical']}")
        if vulnerabilities['medium'] > 0:
            breakdown_text.append(f"🟡 Medium: {vulnerabilities['medium']}")
        if vulnerabilities['low'] > 0:
            breakdown_text.append(f"🟢 Low: {vulnerabilities['low']}")

        if breakdown_text:
            breakdown_widget = {
                "keyValue": {
                    "topLabel": "Vulnerability Breakdown",
                    "content": " | ".join(breakdown_text),
                    "contentMultiline": True,
                    "icon": "WARNING"
                }
            }
            widgets.append(breakdown_widget)

        # Add key insights if available
        insights = executive_summary.get('insights', [])
        if insights:
            insights_text = "\n".join([f"• {insight}" for insight in insights[:3]])  # Show top 3 insights
            insights_widget = {
                "keyValue": {
                    "topLabel": "Key Insights",
                    "content": insights_text,
                    "contentMultiline": True,
                    "icon": "LIGHTBULB"
                }
            }
            widgets.append(insights_widget)

        # Add trend information
        trends = executive_summary.get('trends', {})
        if trends:
            improving = trends.get('improving_targets', 0)
            degrading = trends.get('degrading_targets', 0)
            overall_trend = trends.get('overall_trend', 'stable')

            trend_text = f"Overall: {overall_trend.title()}"
            if improving > 0:
                trend_text += f" | 📉 {improving} improving"
            if degrading > 0:
                trend_text += f" | 📈 {degrading} degrading"

            trend_widget = {
                "keyValue": {
                    "topLabel": "Security Trends",
                    "content": trend_text,
                    "contentMultiline": False,
                    "icon": "TRENDING_UP"
                }
            }
            widgets.append(trend_widget)

        # Add report files if available
        if report_files:
            report_links = []
            for format_type, file_path in report_files.items():
                if os.path.exists(file_path):
                    filename = os.path.basename(file_path)
                    file_size = self._get_human_readable_size(os.path.getsize(file_path))

                    if format_type == 'html_report':
                        report_links.append(f"🌐 Executive Report: {filename} ({file_size})")
                    elif format_type == 'executive_summary':
                        report_links.append(f"📊 Summary JSON: {filename} ({file_size})")
                    elif format_type == 'markdown_summary':
                        report_links.append(f"📝 Summary MD: {filename} ({file_size})")
                    elif 'chart' in format_type:
                        report_links.append(f"📈 Chart: {filename} ({file_size})")
                    else:
                        report_links.append(f"📄 {format_type.title()}: {filename} ({file_size})")

            if report_links:
                reports_widget = {
                    "keyValue": {
                        "topLabel": "📋 Monthly Reports & Charts",
                        "content": "\n".join(report_links),
                        "contentMultiline": True,
                        "icon": "DESCRIPTION"
                    }
                }
                widgets.append(reports_widget)

                # Add download buttons
                buttons = []
                priority_files = ['html_report', 'executive_summary']

                # Add priority file buttons first
                for format_type in priority_files:
                    if format_type in report_files and os.path.exists(report_files[format_type]):
                        filename = os.path.basename(report_files[format_type])
                        button_text = "📊 Executive Report" if format_type == 'html_report' else "📋 Summary Data"
                        buttons.append({
                            "textButton": {
                                "text": button_text,
                                "onClick": {
                                    "openLink": {
                                        "url": f"file://{os.path.abspath(report_files[format_type])}"
                                    }
                                }
                            }
                        })

                if buttons:
                    button_widget = {
                        "buttons": buttons
                    }
                    widgets.append(button_widget)

        # Add timestamp widget
        time_widget = {
            "keyValue": {
                "topLabel": "Report Generated",
                "content": executive_summary.get('scan_date', 'Unknown'),
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