import time
import logging
from typing import Dict, Any, Optional
from zapv2 import ZAPv2
from .config import Config, ScanPolicy
from .docker_manager import DockerManager


logger = logging.getLogger(__name__)


class ZapClient:
    def __init__(self, config: Config):
        self.config = config
        self.docker_manager = None
        self.using_docker = False

        # Check if Docker mode is enabled
        if config.zap_docker and config.zap_docker.enabled:
            self.using_docker = True
            self.docker_manager = DockerManager(config.zap_docker)
            # Use Docker configuration for ZAP connection
            zap_host = "localhost"
            zap_port = config.zap_docker.host_port
            api_key = config.zap_docker.api_key
        else:
            # Use traditional ZAP configuration
            zap_host = config.zap.host
            zap_port = config.zap.port
            api_key = config.zap.api_key

        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                'http': f'http://{zap_host}:{zap_port}',
                'https': f'http://{zap_host}:{zap_port}'
            }
        )

    def start_zap(self) -> bool:
        """Start ZAP (Docker container or ensure external ZAP is running)."""
        if self.using_docker:
            return self.docker_manager.start_zap_container()
        else:
            # For non-Docker mode, just check if ZAP is available
            return self.is_zap_available()

    def stop_zap(self) -> bool:
        """Stop ZAP (Docker container only)."""
        if self.using_docker:
            return self.docker_manager.stop_zap_container()
        else:
            logger.info("ZAP is running externally, not stopping")
            return True

    def is_zap_available(self) -> bool:
        """Check if ZAP is running and accessible."""
        try:
            self.zap.core.version
            return True
        except Exception as e:
            if self.using_docker:
                logger.error(f"ZAP Docker container not available: {e}")
                # Try to check container status for better error reporting
                if self.docker_manager:
                    status = self.docker_manager.get_container_status()
                    if not status.get('running', False):
                        logger.error(f"ZAP container status: {status.get('status', 'unknown')}")
            else:
                logger.error(f"ZAP not available: {e}")
            return False

    def configure_scan_policy(self, policy_name: str, policy: ScanPolicy):
        """Configure ZAP scan policy with optimized settings."""
        try:
            # Configure Spider settings - use action methods for newer ZAP versions
            self.zap.spider.set_option_max_children(policy.spider_max_children)
            self.zap.spider.set_option_max_depth(policy.spider_max_depth)
            self.zap.spider.set_option_max_duration(policy.spider_max_duration)

            # Configure Active Scanner settings - use correct method names
            try:
                self.zap.ascan.set_option_delay_in_ms(policy.ascan_delay_in_ms)
            except AttributeError:
                # Try alternative method name
                self.zap.ascan.set_option_delayinms(policy.ascan_delay_in_ms)

            try:
                self.zap.ascan.set_option_threads_per_host(policy.ascan_threads_per_host)
            except AttributeError:
                # Try alternative method name
                self.zap.ascan.set_option_threadsperhost(policy.ascan_threads_per_host)

            logger.info(f"Configured scan policy: {policy_name}")

        except Exception as e:
            logger.error(f"Failed to configure scan policy {policy_name}: {e}")
            # Don't raise the exception, just log it and continue with default settings
            logger.warning("Continuing with default ZAP settings")

    def spider_scan(self, target_url: str, policy: ScanPolicy) -> str:
        """Run spider scan on target URL."""
        logger.info(f"Starting spider scan on {target_url}")

        # Configure policy first
        self.configure_scan_policy("current", policy)

        # Start spider scan
        scan_id = self.zap.spider.scan(target_url)

        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            logger.info(f"Spider progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)

        logger.info(f"Spider scan completed for {target_url}")
        return scan_id

    def active_scan(self, target_url: str, policy: ScanPolicy) -> str:
        """Run active scan on target URL."""
        logger.info(f"Starting active scan on {target_url}")

        # Start active scan - remove policy parameter as it's not supported in this method
        scan_id = self.zap.ascan.scan(target_url)

        # Wait for active scan to complete
        while int(self.zap.ascan.status(scan_id)) < 100:
            logger.info(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
            time.sleep(5)

        logger.info(f"Active scan completed for {target_url}")
        return scan_id

    def get_alerts(self, target_url: Optional[str] = None) -> list:
        """Get security alerts from ZAP."""
        try:
            if target_url:
                alerts = self.zap.core.alerts(baseurl=target_url)
            else:
                alerts = self.zap.core.alerts()

            return alerts
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    def get_scan_report(self, target_url: str) -> Dict[str, Any]:
        """Generate comprehensive scan report."""
        alerts = self.get_alerts(target_url)

        # Organize alerts by risk level
        report = {
            "target": target_url,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": len(alerts),
            "alerts_by_risk": {
                "High": [],
                "Medium": [],
                "Low": [],
                "Informational": []
            },
            "summary": {
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Informational": 0
            }
        }

        for alert in alerts:
            risk = alert.get("risk", "Informational")
            report["alerts_by_risk"][risk].append(alert)
            report["summary"][risk] += 1

        return report

    def get_zap_status(self) -> Dict[str, Any]:
        """Get detailed ZAP status information."""
        status = {
            "available": self.is_zap_available(),
            "using_docker": self.using_docker,
            "mode": "docker" if self.using_docker else "external"
        }

        if self.using_docker and self.docker_manager:
            container_status = self.docker_manager.get_container_status()
            status.update({
                "container": container_status,
                "docker_url": self.docker_manager.get_zap_url()
            })

        if status["available"]:
            try:
                version = self.zap.core.version
                status["version"] = version
            except Exception as e:
                status["version_error"] = str(e)

        return status

    def cleanup(self):
        """Cleanup ZAP resources."""
        if self.using_docker and self.docker_manager:
            self.docker_manager.cleanup_containers()

    def full_scan(self, target_url: str, policy_name: str = "default") -> Dict[str, Any]:
        """Run complete scan (spider + active scan) and return report."""
        # Auto-start ZAP if using Docker and not available
        if self.using_docker and not self.is_zap_available():
            logger.info("ZAP not available, starting Docker container...")
            if not self.start_zap():
                raise RuntimeError("Failed to start ZAP Docker container")

        if not self.is_zap_available():
            raise RuntimeError("ZAP is not available")

        policy = self.config.scan_policies.get(policy_name)
        if not policy:
            raise ValueError(f"Scan policy '{policy_name}' not found")

        try:
            # Clear previous session
            self.zap.core.new_session()

            # Run spider scan
            self.spider_scan(target_url, policy)

            # Run active scan
            self.active_scan(target_url, policy)

            # Generate report
            report = self.get_scan_report(target_url)

            logger.info(f"Full scan completed for {target_url}")
            return report

        except Exception as e:
            logger.error(f"Scan failed for {target_url}: {e}")
            raise