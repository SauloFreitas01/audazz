import json
import os
import glob
from typing import Dict, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import pandas as pd

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityTrend:
    """Data class for vulnerability trend analysis."""
    month: str
    critical: int
    medium: int
    low: int
    total: int

@dataclass
class TargetSummary:
    """Data class for individual target summary."""
    name: str
    severity: str
    critical: int
    medium: int
    low: int
    informational: int
    total: int
    last_scan: str
    trend: str  # "improving", "stable", "degrading"

class ExecutiveReportGenerator:
    """Generates executive-level security reports with trends and insights."""

    def __init__(self, reports_dir: str = "reports", output_dir: str = "executive-reports"):
        self.reports_dir = reports_dir
        self.output_dir = output_dir
        self.templates_dir = "templates"
        self.ensure_output_dir()

        # Set up Jinja2 environment
        try:
            self.jinja_env = Environment(loader=FileSystemLoader(self.templates_dir))
        except:
            # Fallback to string templates if templates directory doesn't exist
            self.jinja_env = None

    def ensure_output_dir(self):
        """Create output directory if it doesn't exist."""
        os.makedirs(self.output_dir, exist_ok=True)

    def collect_scan_reports(self, days_back: int = 90) -> List[Dict[str, Any]]:
        """Collect all scan reports from the specified time period."""
        reports = []
        cutoff_date = datetime.now() - timedelta(days=days_back)

        if not os.path.exists(self.reports_dir):
            logger.warning(f"Reports directory {self.reports_dir} does not exist")
            return reports

        # Find all JSON report files
        json_files = glob.glob(os.path.join(self.reports_dir, "**", "*.json"), recursive=True)

        for json_file in json_files:
            try:
                # Check file modification time
                file_time = datetime.fromtimestamp(os.path.getmtime(json_file))
                if file_time >= cutoff_date:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                        report_data['file_path'] = json_file
                        report_data['file_time'] = file_time.isoformat()
                        reports.append(report_data)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load report {json_file}: {e}")
                continue

        # Sort by scan time (most recent first)
        reports.sort(key=lambda x: x.get('scan_timestamp', x.get('file_time', '')), reverse=True)

        return reports

    def analyze_target_trends(self, reports: List[Dict[str, Any]]) -> Dict[str, TargetSummary]:
        """Analyze trends for each target over time."""
        target_data = {}

        for report in reports:
            target_name = report.get('target', 'Unknown')
            summary = report.get('summary', {})

            # Initialize target data if not exists
            if target_name not in target_data:
                target_data[target_name] = {
                    'scans': [],
                    'latest_summary': None
                }

            # Add scan data
            scan_data = {
                'timestamp': report.get('scan_timestamp', report.get('file_time', '')),
                'critical': summary.get('High', 0),
                'medium': summary.get('Medium', 0),
                'low': summary.get('Low', 0),
                'informational': summary.get('Informational', 0)
            }
            scan_data['total'] = scan_data['critical'] + scan_data['medium'] + scan_data['low'] + scan_data['informational']

            target_data[target_name]['scans'].append(scan_data)

            # Keep track of latest summary
            if target_data[target_name]['latest_summary'] is None:
                target_data[target_name]['latest_summary'] = scan_data

        # Generate target summaries with trend analysis
        target_summaries = {}
        for target_name, data in target_data.items():
            latest = data['latest_summary'] or {
                'critical': 0, 'medium': 0, 'low': 0, 'informational': 0, 'total': 0, 'timestamp': 'Unknown'
            }

            # Determine severity level
            if latest['critical'] > 0:
                severity = "Critical"
            elif latest['medium'] > 0:
                severity = "Medium"
            elif latest['total'] > 0:
                severity = "Low"
            else:
                severity = "Clean"

            # Calculate trend (simple comparison with previous scan)
            trend = "stable"
            if len(data['scans']) >= 2:
                current_total = data['scans'][0]['total']
                previous_total = data['scans'][1]['total']
                if current_total < previous_total:
                    trend = "improving"
                elif current_total > previous_total:
                    trend = "degrading"

            target_summaries[target_name] = TargetSummary(
                name=target_name,
                severity=severity,
                critical=latest['critical'],
                medium=latest['medium'],
                low=latest['low'],
                informational=latest['informational'],
                total=latest['total'],
                last_scan=latest['timestamp'],
                trend=trend
            )

        return target_summaries

    def generate_vulnerability_trends(self, reports: List[Dict[str, Any]]) -> List[VulnerabilityTrend]:
        """Generate monthly vulnerability trends."""
        monthly_data = {}

        for report in reports:
            timestamp = report.get('scan_timestamp', report.get('file_time', ''))
            try:
                scan_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                month_key = scan_date.strftime('%Y-%m')
            except:
                continue

            if month_key not in monthly_data:
                monthly_data[month_key] = {'critical': 0, 'medium': 0, 'low': 0, 'total': 0}

            summary = report.get('summary', {})
            monthly_data[month_key]['critical'] += summary.get('High', 0)
            monthly_data[month_key]['medium'] += summary.get('Medium', 0)
            monthly_data[month_key]['low'] += summary.get('Low', 0)
            monthly_data[month_key]['total'] += sum(summary.values())

        # Convert to sorted list
        trends = []
        for month, data in sorted(monthly_data.items()):
            trends.append(VulnerabilityTrend(
                month=month,
                critical=data['critical'],
                medium=data['medium'],
                low=data['low'],
                total=data['total']
            ))

        return trends

    def generate_charts(self, target_summaries: Dict[str, TargetSummary],
                       trends: List[VulnerabilityTrend]) -> Dict[str, str]:
        """Generate visualization charts for the executive report."""
        chart_files = {}

        try:
            # Set up matplotlib for headless operation
            plt.switch_backend('Agg')

            # 1. Target Risk Summary Chart
            if target_summaries:
                targets = list(target_summaries.keys())
                critical_counts = [ts.critical for ts in target_summaries.values()]
                medium_counts = [ts.medium for ts in target_summaries.values()]
                low_counts = [ts.low for ts in target_summaries.values()]

                fig, ax = plt.subplots(figsize=(12, 6))
                x = range(len(targets))

                # Stacked bar chart
                ax.bar(x, critical_counts, label='Critical', color='#dc3545')
                ax.bar(x, medium_counts, bottom=critical_counts, label='Medium', color='#fd7e14')
                bottom = [c + m for c, m in zip(critical_counts, medium_counts)]
                ax.bar(x, low_counts, bottom=bottom, label='Low', color='#ffc107')

                ax.set_xlabel('Targets')
                ax.set_ylabel('Vulnerability Count')
                ax.set_title('Security Risk by Target')
                ax.set_xticks(x)
                ax.set_xticklabels(targets, rotation=45, ha='right')
                ax.legend()

                plt.tight_layout()
                chart_path = os.path.join(self.output_dir, 'target_risk_summary.png')
                plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                plt.close()
                chart_files['target_risk'] = chart_path

            # 2. Vulnerability Trends Chart
            if trends:
                months = [t.month for t in trends]
                critical_trend = [t.critical for t in trends]
                medium_trend = [t.medium for t in trends]
                total_trend = [t.total for t in trends]

                fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))

                # Critical and Medium trends
                ax1.plot(months, critical_trend, marker='o', color='#dc3545', label='Critical', linewidth=2)
                ax1.plot(months, medium_trend, marker='s', color='#fd7e14', label='Medium', linewidth=2)
                ax1.set_title('Critical and Medium Vulnerability Trends')
                ax1.set_ylabel('Count')
                ax1.legend()
                ax1.grid(True, alpha=0.3)

                # Total vulnerabilities trend
                ax2.plot(months, total_trend, marker='o', color='#28a745', linewidth=2)
                ax2.set_title('Total Vulnerabilities Trend')
                ax2.set_xlabel('Month')
                ax2.set_ylabel('Total Count')
                ax2.grid(True, alpha=0.3)

                # Rotate x-axis labels
                for ax in [ax1, ax2]:
                    ax.tick_params(axis='x', rotation=45)

                plt.tight_layout()
                chart_path = os.path.join(self.output_dir, 'vulnerability_trends.png')
                plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                plt.close()
                chart_files['trends'] = chart_path

        except Exception as e:
            logger.warning(f"Failed to generate charts: {e}")

        return chart_files

    def generate_executive_summary(self, target_summaries: Dict[str, TargetSummary],
                                 trends: List[VulnerabilityTrend]) -> Dict[str, Any]:
        """Generate executive-level summary and insights."""
        # Calculate overall statistics
        total_targets = len(target_summaries)
        total_critical = sum(ts.critical for ts in target_summaries.values())
        total_medium = sum(ts.medium for ts in target_summaries.values())
        total_low = sum(ts.low for ts in target_summaries.values())
        total_vulns = total_critical + total_medium + total_low

        # Determine overall risk level
        if total_critical > 0:
            overall_risk = "Critical"
            risk_color = "#dc3545"
            risk_emoji = "🔴"
        elif total_medium > 0:
            overall_risk = "Medium"
            risk_color = "#fd7e14"
            risk_emoji = "🟡"
        elif total_vulns > 0:
            overall_risk = "Low"
            risk_color = "#ffc107"
            risk_emoji = "🟢"
        else:
            overall_risk = "Clean"
            risk_color = "#28a745"
            risk_emoji = "✅"

        # Calculate target distribution by risk
        risk_distribution = {"Critical": 0, "Medium": 0, "Low": 0, "Clean": 0}
        improving_targets = 0
        degrading_targets = 0

        for ts in target_summaries.values():
            risk_distribution[ts.severity] += 1
            if ts.trend == "improving":
                improving_targets += 1
            elif ts.trend == "degrading":
                degrading_targets += 1

        # Generate insights and recommendations
        insights = []
        recommendations = []

        if total_critical > 0:
            insights.append(f"🚨 {total_critical} critical vulnerabilities require immediate attention")
            recommendations.append("Schedule emergency patching for all critical vulnerabilities within 24-48 hours")

        if total_medium > 0:
            insights.append(f"⚠️ {total_medium} medium-risk vulnerabilities identified across the infrastructure")
            recommendations.append("Plan remediation for medium-risk vulnerabilities within 30 days")

        if degrading_targets > 0:
            insights.append(f"📈 {degrading_targets} targets show degrading security posture")
            recommendations.append("Investigate root causes for security posture degradation")

        if improving_targets > 0:
            insights.append(f"📉 {improving_targets} targets show improving security trends")

        if total_vulns == 0:
            insights.append("✅ No vulnerabilities detected across all scanned targets")
            recommendations.append("Maintain current security practices and continue regular assessments")

        # Trend analysis
        trend_analysis = "stable"
        if len(trends) >= 2:
            latest_total = trends[0].total if trends else 0
            previous_total = trends[1].total if len(trends) > 1 else 0
            if latest_total < previous_total:
                trend_analysis = "improving"
            elif latest_total > previous_total:
                trend_analysis = "degrading"

        return {
            "scan_date": datetime.now().isoformat(),
            "scan_month": datetime.now().strftime("%B %Y"),
            "overall_risk": overall_risk,
            "risk_color": risk_color,
            "risk_emoji": risk_emoji,
            "total_targets": total_targets,
            "vulnerabilities": {
                "critical": total_critical,
                "medium": total_medium,
                "low": total_low,
                "total": total_vulns
            },
            "risk_distribution": risk_distribution,
            "trends": {
                "improving_targets": improving_targets,
                "degrading_targets": degrading_targets,
                "overall_trend": trend_analysis
            },
            "insights": insights,
            "recommendations": recommendations,
            "target_summaries": {name: {
                "name": ts.name,
                "severity": ts.severity,
                "critical": ts.critical,
                "medium": ts.medium,
                "low": ts.low,
                "total": ts.total,
                "trend": ts.trend,
                "last_scan": ts.last_scan
            } for name, ts in target_summaries.items()}
        }

    def generate_html_report(self, executive_summary: Dict[str, Any],
                           chart_files: Dict[str, str]) -> str:
        """Generate HTML executive report."""
        html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Monthly Security Executive Report - {{ summary.scan_month }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid #007bff; }
        .metric-value { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .risk-critical { border-left-color: #dc3545; }
        .risk-medium { border-left-color: #fd7e14; }
        .risk-low { border-left-color: #ffc107; }
        .risk-clean { border-left-color: #28a745; }
        .section { margin: 30px 0; }
        .insights { background: #e3f2fd; border-radius: 8px; padding: 20px; }
        .recommendations { background: #fff3e0; border-radius: 8px; padding: 20px; }
        .target-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
        .target-card { background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; }
        .trend-up { color: #28a745; }
        .trend-down { color: #dc3545; }
        .trend-stable { color: #6c757d; }
        .chart-container { text-align: center; margin: 20px 0; }
        .chart-container img { max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ summary.risk_emoji }} Monthly Security Executive Report</h1>
            <h2>{{ summary.scan_month }}</h2>
            <p>Comprehensive Security Assessment Summary</p>
        </div>

        <div class="content">
            <div class="section">
                <h2>Executive Overview</h2>
                <div class="metric-grid">
                    <div class="metric-card risk-{{ summary.overall_risk.lower() }}">
                        <div class="metric-label">Overall Risk Level</div>
                        <div class="metric-value" style="color: {{ summary.risk_color }}">{{ summary.risk_emoji }} {{ summary.overall_risk }}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Targets Scanned</div>
                        <div class="metric-value">{{ summary.total_targets }}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Total Vulnerabilities</div>
                        <div class="metric-value">{{ summary.vulnerabilities.total }}</div>
                    </div>
                    <div class="metric-card risk-critical">
                        <div class="metric-label">Critical Issues</div>
                        <div class="metric-value" style="color: #dc3545">{{ summary.vulnerabilities.critical }}</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Vulnerability Breakdown</h2>
                <div class="metric-grid">
                    <div class="metric-card risk-critical">
                        <div class="metric-label">🔴 Critical</div>
                        <div class="metric-value">{{ summary.vulnerabilities.critical }}</div>
                    </div>
                    <div class="metric-card risk-medium">
                        <div class="metric-label">🟡 Medium</div>
                        <div class="metric-value">{{ summary.vulnerabilities.medium }}</div>
                    </div>
                    <div class="metric-card risk-low">
                        <div class="metric-label">🟢 Low</div>
                        <div class="metric-value">{{ summary.vulnerabilities.low }}</div>
                    </div>
                </div>
            </div>

            {% if charts.target_risk %}
            <div class="section">
                <h2>Target Risk Distribution</h2>
                <div class="chart-container">
                    <img src="{{ charts.target_risk }}" alt="Target Risk Summary Chart">
                </div>
            </div>
            {% endif %}

            {% if charts.trends %}
            <div class="section">
                <h2>Vulnerability Trends</h2>
                <div class="chart-container">
                    <img src="{{ charts.trends }}" alt="Vulnerability Trends Chart">
                </div>
            </div>
            {% endif %}

            <div class="section">
                <h2>Key Insights</h2>
                <div class="insights">
                    <h3>🔍 Analysis</h3>
                    <ul>
                        {% for insight in summary.insights %}
                        <li>{{ insight }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                <div class="recommendations">
                    <h3>📋 Action Items</h3>
                    <ol>
                        {% for recommendation in summary.recommendations %}
                        <li>{{ recommendation }}</li>
                        {% endfor %}
                    </ol>
                </div>
            </div>

            <div class="section">
                <h2>Target Details</h2>
                <div class="target-list">
                    {% for target_name, target in summary.target_summaries.items() %}
                    <div class="target-card">
                        <h4>{{ target.name }}</h4>
                        <p><strong>Risk Level:</strong> {{ target.severity }}</p>
                        <p><strong>Vulnerabilities:</strong> Critical({{ target.critical }}), Medium({{ target.medium }}), Low({{ target.low }})</p>
                        <p><strong>Trend:</strong>
                            <span class="trend-{{ target.trend }}">
                                {% if target.trend == 'improving' %}📉 Improving
                                {% elif target.trend == 'degrading' %}📈 Degrading
                                {% else %}➡️ Stable
                                {% endif %}
                            </span>
                        </p>
                        <p><strong>Last Scan:</strong> {{ target.last_scan }}</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
        '''

        try:
            from jinja2 import Template
            template = Template(html_template)
            html_content = template.render(summary=executive_summary, charts=chart_files)

            # Save HTML report
            html_path = os.path.join(self.output_dir, f"executive_report_{datetime.now().strftime('%Y%m%d')}.html")
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML executive report generated: {html_path}")
            return html_path

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def generate_monthly_executive_report(self) -> Dict[str, str]:
        """Generate complete monthly executive report."""
        try:
            logger.info("Starting monthly executive report generation...")

            # Collect scan reports from the last 90 days
            reports = self.collect_scan_reports(days_back=90)
            logger.info(f"Collected {len(reports)} scan reports")

            if not reports:
                logger.warning("No scan reports found for executive report generation")
                return {}

            # Analyze target trends
            target_summaries = self.analyze_target_trends(reports)
            logger.info(f"Analyzed {len(target_summaries)} targets")

            # Generate vulnerability trends
            trends = self.generate_vulnerability_trends(reports)
            logger.info(f"Generated {len(trends)} monthly trend data points")

            # Generate executive summary
            executive_summary = self.generate_executive_summary(target_summaries, trends)

            # Generate charts
            chart_files = self.generate_charts(target_summaries, trends)
            logger.info(f"Generated {len(chart_files)} charts")

            # Save executive summary as JSON
            summary_path = os.path.join(self.output_dir, "executive_summary.json")
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(executive_summary, f, indent=2, ensure_ascii=False)

            # Generate HTML report
            html_path = self.generate_html_report(executive_summary, chart_files)

            # Generate markdown summary for notifications
            md_path = self.generate_markdown_summary(executive_summary)

            generated_files = {
                "executive_summary": summary_path,
                "html_report": html_path,
                "markdown_summary": md_path
            }
            generated_files.update(chart_files)

            logger.info(f"Executive report generation completed. Files: {list(generated_files.keys())}")
            return generated_files

        except Exception as e:
            logger.error(f"Failed to generate executive report: {e}")
            raise

    def generate_markdown_summary(self, executive_summary: Dict[str, Any]) -> str:
        """Generate markdown summary for notifications."""
        md_content = f"""# Monthly Security Scan Executive Summary

**Scan Date:** {executive_summary['scan_month']}
**Overall Risk Level:** {executive_summary['risk_emoji']} {executive_summary['overall_risk']}

## Key Metrics
- **Targets Scanned:** {executive_summary['total_targets']}
- **Total Vulnerabilities:** {executive_summary['vulnerabilities']['total']}
- **Critical:** {executive_summary['vulnerabilities']['critical']}
- **Medium:** {executive_summary['vulnerabilities']['medium']}
- **Low:** {executive_summary['vulnerabilities']['low']}

## Target Breakdown
"""

        for target_name, target in executive_summary['target_summaries'].items():
            severity_emoji = "🔴" if target['critical'] > 0 else "🟡" if target['medium'] > 0 else "🟢" if target['total'] > 0 else "✅"
            trend_emoji = "📉" if target['trend'] == 'improving' else "📈" if target['trend'] == 'degrading' else "➡️"

            md_content += f"""
### {target['name']} {severity_emoji}
- **Risk Level:** {target['severity']}
- **Vulnerabilities:** Critical({target['critical']}), Medium({target['medium']}), Low({target['low']})
- **Trend:** {trend_emoji} {target['trend'].title()}
"""

        md_content += f"""

## Key Insights
"""
        for insight in executive_summary['insights']:
            md_content += f"- {insight}\n"

        md_content += f"""
## Recommendations
"""
        for i, recommendation in enumerate(executive_summary['recommendations'], 1):
            md_content += f"{i}. {recommendation}\n"

        # Save markdown file
        md_path = os.path.join(self.output_dir, "summary.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

        logger.info(f"Markdown summary generated: {md_path}")
        return md_path