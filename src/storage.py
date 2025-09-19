import json
import os
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml


class FileStorage:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.ensure_directories()

    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "scans"), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "targets"), exist_ok=True)

    def save_scan_result(self, target_name: str, scan_result: Dict[str, Any]) -> str:
        """Save scan result to file and return file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target_name}_{timestamp}.json"
        filepath = os.path.join(self.data_dir, "scans", filename)

        scan_data = {
            "scan_id": f"{target_name}_{timestamp}",
            "target_name": target_name,
            "timestamp": timestamp,
            "scan_result": scan_result
        }

        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)

        return filepath

    def get_scan_history(self, target_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get scan history for a target or all targets."""
        scans_dir = os.path.join(self.data_dir, "scans")
        scan_files = []

        if not os.path.exists(scans_dir):
            return []

        for filename in os.listdir(scans_dir):
            if filename.endswith('.json'):
                if target_name is None or filename.startswith(f"{target_name}_"):
                    filepath = os.path.join(scans_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            scan_data = json.load(f)
                            scan_files.append(scan_data)
                    except json.JSONDecodeError:
                        continue

        # Sort by timestamp (newest first)
        scan_files.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return scan_files

    def get_latest_scan(self, target_name: str) -> Optional[Dict[str, Any]]:
        """Get the latest scan result for a target."""
        history = self.get_scan_history(target_name)
        return history[0] if history else None

    def save_target_status(self, target_name: str, status_data: Dict[str, Any]):
        """Save target status information."""
        filepath = os.path.join(self.data_dir, "targets", f"{target_name}.yaml")

        with open(filepath, 'w') as f:
            yaml.dump(status_data, f, default_flow_style=False, indent=2)

    def get_target_status(self, target_name: str) -> Optional[Dict[str, Any]]:
        """Get target status information."""
        filepath = os.path.join(self.data_dir, "targets", f"{target_name}.yaml")

        if not os.path.exists(filepath):
            return None

        with open(filepath, 'r') as f:
            return yaml.safe_load(f)

    def get_all_target_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get status information for all targets."""
        targets_dir = os.path.join(self.data_dir, "targets")
        statuses = {}

        if not os.path.exists(targets_dir):
            return {}

        for filename in os.listdir(targets_dir):
            if filename.endswith('.yaml'):
                target_name = filename[:-5]  # Remove .yaml extension
                status = self.get_target_status(target_name)
                if status:
                    statuses[target_name] = status

        return statuses

    def update_scan_stats(self, target_name: str, scan_result: Dict[str, Any]):
        """Update target statistics based on scan result."""
        current_status = self.get_target_status(target_name) or {}

        # Update statistics
        stats = current_status.get('stats', {})
        stats['total_scans'] = stats.get('total_scans', 0) + 1
        stats['last_scan'] = datetime.now().isoformat()

        # Update vulnerability counts
        summary = scan_result.get('summary', {})
        stats['last_vulnerabilities'] = {
            'high': summary.get('High', 0),
            'medium': summary.get('Medium', 0),
            'low': summary.get('Low', 0),
            'informational': summary.get('Informational', 0)
        }

        # Calculate trends (compare with previous scan)
        history = self.get_scan_history(target_name)
        if len(history) >= 2:
            prev_scan = history[1]['scan_result'].get('summary', {})
            current_scan = summary

            trends = {}
            for risk in ['High', 'Medium', 'Low', 'Informational']:
                prev_count = prev_scan.get(risk, 0)
                current_count = current_scan.get(risk, 0)
                trends[risk.lower()] = current_count - prev_count

            stats['trends'] = trends

        current_status['stats'] = stats
        self.save_target_status(target_name, current_status)

    def cleanup_old_scans(self, days_to_keep: int = 30):
        """Clean up scan files older than specified days."""
        scans_dir = os.path.join(self.data_dir, "scans")

        if not os.path.exists(scans_dir):
            return

        cutoff_time = time.time() - (days_to_keep * 24 * 60 * 60)

        for filename in os.listdir(scans_dir):
            filepath = os.path.join(scans_dir, filename)
            if os.path.getmtime(filepath) < cutoff_time:
                os.remove(filepath)