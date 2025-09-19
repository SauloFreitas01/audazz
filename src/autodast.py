import logging
import signal
import sys
from typing import Dict, Any, Optional
from .config import Config, load_config, save_config, Target
from .zap_client import ZapClient
from .scheduler import ScanScheduler
from .storage import FileStorage
from .report_generator import ReportGenerator
from .google_chat import GoogleChatNotifier


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AutoDast:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = load_config(config_path)
        self.zap_client = ZapClient(self.config)
        self.storage = FileStorage()
        self.report_generator = ReportGenerator(
            output_dir=self.config.reports.output_dir,
            templates_dir="templates"
        )
        self.google_chat = GoogleChatNotifier(self.config.google_chat.webhook_url)
        self.scheduler = ScanScheduler(self._execute_scan)
        self.running = False

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info("Received shutdown signal, stopping AutoDast...")
        self.stop()
        sys.exit(0)

    def start(self):
        """Start the AutoDast monitoring system."""
        logger.info("Starting AutoDast security monitoring system...")

        # Start ZAP if using Docker mode
        if self.zap_client.using_docker:
            logger.info("Starting ZAP Docker container...")
            if not self.zap_client.start_zap():
                logger.error("Failed to start ZAP Docker container.")
                return False

        # Verify ZAP is available
        if not self.zap_client.is_zap_available():
            if self.zap_client.using_docker:
                logger.error("ZAP Docker container is not responding. Check Docker and container logs.")
            else:
                logger.error("OWASP ZAP is not available. Please start ZAP before running AutoDast.")
            return False

        # Schedule periodic scans for all targets
        for target in self.config.targets:
            self.scheduler.schedule_target(
                target.name,
                target.url,
                self.config.scheduler.interval_hours,
                target.scan_policy
            )

        # Start the scheduler
        self.scheduler.start()
        self.running = True

        # Send startup notification
        if self.config.google_chat.webhook_url:
            zap_status = self.zap_client.get_zap_status()
            self.google_chat.send_status_notification(
                "AutoDast monitoring system started successfully",
                {
                    "Targets Monitored": len(self.config.targets),
                    "Scan Interval": f"{self.config.scheduler.interval_hours} hours",
                    "ZAP Mode": zap_status.get("mode", "unknown"),
                    "ZAP Version": zap_status.get("version", "unknown")
                }
            )

        logger.info(f"AutoDast started successfully - monitoring {len(self.config.targets)} targets")
        return True

    def stop(self):
        """Stop the AutoDast monitoring system."""
        if self.running:
            logger.info("Stopping AutoDast...")
            self.scheduler.stop()

            # Stop ZAP Docker container if running
            if self.zap_client.using_docker:
                logger.info("Stopping ZAP Docker container...")
                self.zap_client.stop_zap()

            self.running = False
            logger.info("AutoDast stopped")

    def _execute_scan(self, target_url: str, scan_policy: str) -> Dict[str, Any]:
        """Execute a scan and handle results."""
        target_name = self._get_target_name_by_url(target_url)

        try:
            # Perform the scan
            scan_result = self.zap_client.full_scan(target_url, scan_policy)

            # Store scan result
            scan_file = self.storage.save_scan_result(target_name, scan_result)

            # Update target statistics
            self.storage.update_scan_stats(target_name, scan_result)

            # Generate reports
            report_files = self.report_generator.generate_reports(
                scan_result,
                target_name,
                self.config.reports.formats
            )

            # Send notification if configured
            if self.config.google_chat.webhook_url:
                summary = self.report_generator.generate_summary_report(scan_result)
                self.google_chat.send_scan_notification(summary)

            logger.info(f"Scan completed successfully for {target_name}")
            return {
                "success": True,
                "scan_result": scan_result,
                "scan_file": scan_file,
                "report_files": report_files
            }

        except Exception as e:
            error_msg = f"Scan failed for {target_name}: {str(e)}"
            logger.error(error_msg)

            # Send error notification if configured
            if self.config.google_chat.webhook_url:
                self.google_chat.send_error_notification(target_name, error_msg)

            return {
                "success": False,
                "error": error_msg
            }

    def execute_manual_scan(self, target_name: str, scan_policy: str = None, target_url: str = None) -> Dict[str, Any]:
        """Execute a manual scan for a specific target."""
        target = self._get_target_by_name(target_name)
        target_added = False

        # If target doesn't exist and URL is provided, create it dynamically
        if not target and target_url:
            logger.info(f"Target '{target_name}' not found, creating dynamic target for URL: {target_url}")
            target = self._create_dynamic_target(target_name, target_url, scan_policy)
            target_added = True
        elif not target:
            raise ValueError(f"Target '{target_name}' not found in configuration and no URL provided")

        policy = scan_policy or target.scan_policy

        logger.info(f"Starting manual scan for {target_name}")

        try:
            result = self.scheduler.execute_manual_scan(
                target_name,
                target.url,
                policy
            )

            if result and result.get("success"):
                logger.info(f"Manual scan completed successfully for {target_name}")
                result["target_added"] = target_added
            else:
                logger.error(f"Manual scan failed for {target_name}")

            return result

        except Exception as e:
            error_msg = f"Manual scan failed for {target_name}: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }

    def get_target_status(self, target_name: str = None) -> Dict[str, Any]:
        """Get status information for targets."""
        if target_name:
            status = self.storage.get_target_status(target_name)
            latest_scan = self.storage.get_latest_scan(target_name)
            return {
                "target": target_name,
                "status": status,
                "latest_scan": latest_scan
            }
        else:
            statuses = self.storage.get_all_target_statuses()
            scheduler_status = self.scheduler.get_scheduler_status()
            return {
                "scheduler": scheduler_status,
                "targets": statuses
            }

    def get_scan_history(self, target_name: str = None, limit: int = 10) -> list:
        """Get scan history for targets."""
        return self.storage.get_scan_history(target_name)[:limit]

    def add_target(self, name: str, url: str, scan_policy: str = "default"):
        """Add a new target for monitoring."""
        # Add to configuration (this would need to persist to config file)
        new_target = {
            "name": name,
            "url": url,
            "scan_policy": scan_policy
        }

        # Schedule the new target
        self.scheduler.schedule_target(
            name,
            url,
            self.config.scheduler.interval_hours,
            scan_policy
        )

        logger.info(f"Added new target: {name} ({url})")

    def remove_target(self, target_name: str):
        """Remove a target from monitoring."""
        self.scheduler.unschedule_target(target_name)
        logger.info(f"Removed target: {target_name}")

    def test_google_chat_webhook(self) -> bool:
        """Test Google Chat webhook connectivity."""
        return self.google_chat.test_webhook()

    def cleanup_old_data(self, days_to_keep: int = 30):
        """Clean up old scan data."""
        self.storage.cleanup_old_scans(days_to_keep)
        logger.info(f"Cleaned up scan data older than {days_to_keep} days")

    def _get_target_by_name(self, target_name: str):
        """Get target configuration by name."""
        for target in self.config.targets:
            if target.name == target_name:
                return target
        return None

    def _get_target_name_by_url(self, target_url: str) -> str:
        """Get target name by URL."""
        for target in self.config.targets:
            if target.url == target_url:
                return target.name
        return "unknown"

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        zap_status = self.zap_client.get_zap_status()
        return {
            "running": self.running,
            "zap_available": zap_status["available"],
            "zap_status": zap_status,
            "scheduler_status": self.scheduler.get_scheduler_status(),
            "targets_count": len(self.config.targets),
            "webhook_configured": bool(self.config.google_chat.webhook_url)
        }

    def get_zap_logs(self) -> str:
        """Get ZAP container logs (Docker mode only)."""
        if self.zap_client.using_docker and self.zap_client.docker_manager:
            return self.zap_client.docker_manager.get_container_logs()
        else:
            return "ZAP logs not available (not using Docker mode)"

    def restart_zap(self) -> bool:
        """Restart ZAP (Docker mode only)."""
        if self.zap_client.using_docker and self.zap_client.docker_manager:
            return self.zap_client.docker_manager.restart_container()
        else:
            logger.warning("Restart not supported for external ZAP instances")
            return False

    def _create_dynamic_target(self, target_name: str, target_url: str, scan_policy: str = None) -> Target:
        """Create a new target dynamically and add it to configuration."""
        # Create new target
        new_target = Target(
            name=target_name,
            url=target_url,
            scan_policy=scan_policy or "default"
        )

        # Add to current configuration
        self.config.targets.append(new_target)

        # Persist to configuration file
        self._save_config()

        logger.info(f"Added new target '{target_name}' with URL '{target_url}' to configuration")
        return new_target

    def _save_config(self):
        """Save current configuration to file."""
        try:
            save_config(self.config, self.config_path)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise

    def add_target_to_config(self, name: str, url: str, scan_policy: str = "default", persist: bool = True) -> Target:
        """Add a new target to the configuration."""
        # Check if target already exists
        existing_target = self._get_target_by_name(name)
        if existing_target:
            logger.warning(f"Target '{name}' already exists, updating URL and policy")
            existing_target.url = url
            existing_target.scan_policy = scan_policy
            if persist:
                self._save_config()
            return existing_target

        # Create new target
        return self._create_dynamic_target(name, url, scan_policy)