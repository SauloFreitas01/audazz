import json
import os
from typing import Dict, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import logging


logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, output_dir: str = "reports", templates_dir: str = "templates"):
        self.output_dir = output_dir
        self.templates_dir = templates_dir
        self.jinja_env = Environment(loader=FileSystemLoader(templates_dir))
        self.ensure_output_dir()

    def ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_html_report(self, scan_result: Dict[str, Any], target_name: str) -> str:
        """Generate HTML report from scan results."""
        try:
            template = self.jinja_env.get_template('report.html')
            html_content = template.render(report=scan_result)

            # Create filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{target_name}_{timestamp}.html"
            filepath = os.path.join(self.output_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def generate_json_report(self, scan_result: Dict[str, Any], target_name: str) -> str:
        """Generate JSON report from scan results."""
        try:
            # Create filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{target_name}_{timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(scan_result, f, indent=2, ensure_ascii=False)

            logger.info(f"JSON report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise

    def generate_summary_report(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary report for notifications."""
        summary = scan_result.get('summary', {})
        target = scan_result.get('target', 'Unknown')

        total_vulnerabilities = sum(summary.values())
        critical_count = summary.get('High', 0)
        medium_count = summary.get('Medium', 0)

        # Determine severity level for the overall scan
        if critical_count > 0:
            severity = "🔴 Critical"
            color = "#dc3545"
        elif medium_count > 0:
            severity = "🟡 Medium"
            color = "#fd7e14"
        elif total_vulnerabilities > 0:
            severity = "🟢 Low"
            color = "#28a745"
        else:
            severity = "✅ Clean"
            color = "#28a745"

        return {
            "target": target,
            "severity": severity,
            "color": color,
            "total_vulnerabilities": total_vulnerabilities,
            "breakdown": {
                "high": summary.get('High', 0),
                "medium": summary.get('Medium', 0),
                "low": summary.get('Low', 0),
                "informational": summary.get('Informational', 0)
            },
            "scan_timestamp": scan_result.get('scan_timestamp', 'Unknown'),
            "top_vulnerabilities": self._get_top_vulnerabilities(scan_result)
        }

    def _get_top_vulnerabilities(self, scan_result: Dict[str, Any], limit: int = 5) -> list:
        """Get top vulnerabilities by severity."""
        top_vulns = []

        # Prioritize High and Medium risk vulnerabilities
        for risk_level in ['High', 'Medium']:
            alerts = scan_result.get('alerts_by_risk', {}).get(risk_level, [])
            for alert in alerts[:limit - len(top_vulns)]:
                top_vulns.append({
                    "name": alert.get('name', 'Unknown'),
                    "risk": risk_level,
                    "url": alert.get('url', '')
                })

                if len(top_vulns) >= limit:
                    break

            if len(top_vulns) >= limit:
                break

        return top_vulns

    def generate_reports(self, scan_result: Dict[str, Any], target_name: str,
                        formats: list = None) -> Dict[str, str]:
        """Generate reports in multiple formats."""
        if formats is None:
            formats = ['html', 'json']

        generated_files = {}

        try:
            if 'html' in formats:
                html_file = self.generate_html_report(scan_result, target_name)
                generated_files['html'] = html_file

            if 'json' in formats:
                json_file = self.generate_json_report(scan_result, target_name)
                generated_files['json'] = json_file

            logger.info(f"Generated {len(generated_files)} report files for {target_name}")
            return generated_files

        except Exception as e:
            logger.error(f"Failed to generate reports for {target_name}: {e}")
            raise

    def get_report_files(self, target_name: str = None, limit: int = None) -> list:
        """Get list of existing report files."""
        if not os.path.exists(self.output_dir):
            return []

        files = []
        for filename in os.listdir(self.output_dir):
            if target_name is None or filename.startswith(f"{target_name}_"):
                filepath = os.path.join(self.output_dir, filename)
                file_info = {
                    "filename": filename,
                    "filepath": filepath,
                    "size": os.path.getsize(filepath),
                    "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                }
                files.append(file_info)

        # Sort by modification time (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)

        if limit:
            files = files[:limit]

        return files