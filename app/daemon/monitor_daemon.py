#!/usr/bin/env python3
"""
DAST Monitor Daemon - Continuous Monitoring Service
Bare Version - File-based continuous security scanning
"""

import asyncio
import signal
import sys
import os
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import json
import yaml

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.dast_monitor import DASTMonitor, ScanTarget, ScanResult


class MonitorDaemon:
    """Continuous monitoring daemon for DAST security scanning"""
    
    def __init__(self, config_path: str = "config/dast_config.yaml"):
        self.config_path = config_path
        self.monitor = None
        self.running = False
        self.check_interval = 60  # Check every minute
        self.last_maintenance = None
        self.maintenance_interval = 3600  # Run maintenance every hour
        
        # Setup logging
        self._setup_logging()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Load configuration
        self.config = self._load_config()
        
    def _setup_logging(self):
        """Setup daemon logging"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('logs/monitor_daemon.log')
            ]
        )
        self.logger = logging.getLogger('monitor_daemon')
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return {}
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        
    async def start(self):
        """Start the continuous monitoring daemon"""
        self.logger.info("Starting DAST Monitor Daemon - Bare Version")
        self.logger.info("=" * 50)
        
        try:
            # Initialize DAST Monitor
            self.monitor = DASTMonitor(self.config_path)
            self.running = True
            self.last_maintenance = datetime.now()
            
            # Load targets from configuration or database
            await self._load_targets()
            
            self.logger.info(f"Daemon started with {len(self.monitor.targets)} targets")
            self.logger.info(f"Check interval: {self.check_interval} seconds")
            
            # Main monitoring loop
            await self._monitoring_loop()
            
        except Exception as e:
            self.logger.error(f"Failed to start daemon: {e}")
            raise
    
    async def _load_targets(self):
        """Load monitoring targets from configuration or discover from reports"""
        targets_config = self.config.get('targets', [])
        
        if targets_config:
            # Load from configuration
            for target_config in targets_config:
                target = ScanTarget(
                    domain=target_config['domain'],
                    subdomains=target_config.get('subdomains', []),
                    scan_type=target_config.get('scan_type', 'standard'),
                    priority=target_config.get('priority', 1)
                )
                self.monitor.add_target(target)
                self.logger.info(f"Added target from config: {target.domain}")
        else:
            # Discover targets from existing reports
            await self._discover_targets_from_reports()
    
    async def _discover_targets_from_reports(self):
        """Discover targets from existing reports directory"""
        reports_dir = Path(self.config.get('reports', {}).get('export_path', 'reports'))
        
        if not reports_dir.exists():
            self.logger.warning(f"Reports directory not found: {reports_dir}")
            return
        
        # Find domain directories
        for domain_dir in reports_dir.iterdir():
            if domain_dir.is_dir() and not domain_dir.name.startswith('.'):
                domain = domain_dir.name
                subdomains = []
                
                # Check for subdomain directories
                subdomains_dir = domain_dir / 'subdomains'
                if subdomains_dir.exists():
                    for sub_dir in subdomains_dir.iterdir():
                        if sub_dir.is_dir():
                            subdomains.append(sub_dir.name)
                
                target = ScanTarget(
                    domain=domain,
                    subdomains=subdomains,
                    scan_type='standard',
                    priority=2  # Default medium priority
                )
                self.monitor.add_target(target)
                self.logger.info(f"Discovered target: {domain} with {len(subdomains)} subdomains")
    
    async def _monitoring_loop(self):
        """Main continuous monitoring loop"""
        self.logger.info("Starting continuous monitoring loop...")
        
        while self.running:
            try:
                # Check for scheduled scans
                await self._check_scheduled_scans()
                
                # Run maintenance if needed
                await self._check_maintenance()
                
                # Sleep before next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                self.logger.info("Monitoring loop cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                # Continue running even if there's an error
                await asyncio.sleep(self.check_interval)
        
        self.logger.info("Monitoring loop stopped")
    
    async def _check_scheduled_scans(self):
        """Check if any targets are due for scanning"""
        current_time = datetime.now()
        scans_triggered = 0
        
        for target in self.monitor.targets:
            if target.next_scan is None or current_time >= target.next_scan:
                try:
                    self.logger.info(f"Triggering scan for {target.domain} (priority {target.priority})")
                    
                    # Run the scan
                    success = await self._run_target_scan(target)
                    
                    if success:
                        # Update scan timestamps
                        target.last_scan = current_time
                        target.next_scan = self.monitor._calculate_next_scan(target.priority)
                        scans_triggered += 1
                        
                        self.logger.info(f"Scan completed for {target.domain}. Next scan: {target.next_scan}")
                    else:
                        # Retry later if scan failed
                        target.next_scan = current_time + timedelta(minutes=10)
                        self.logger.warning(f"Scan failed for {target.domain}. Retry at: {target.next_scan}")
                        
                except Exception as e:
                    self.logger.error(f"Error scanning {target.domain}: {e}")
                    # Schedule retry
                    target.next_scan = current_time + timedelta(minutes=15)
        
        if scans_triggered > 0:
            self.logger.info(f"Triggered {scans_triggered} scans in this cycle")
    
    async def _run_target_scan(self, target: ScanTarget) -> bool:
        """Run a scan for a specific target"""
        try:
            # Main domain scan
            main_result = await self._scan_domain(target.domain, target.scan_type)
            if not main_result:
                return False
            
            # Subdomain scans
            subdomain_results = []
            for subdomain in target.subdomains[:5]:  # Limit to 5 subdomains per cycle
                subdomain_url = f"{subdomain}.{target.domain}"
                result = await self._scan_domain(subdomain_url, target.scan_type)
                if result:
                    subdomain_results.append(result)
            
            # Process and store results
            all_results = [main_result] + subdomain_results
            await self._process_scan_results(target, all_results)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to scan target {target.domain}: {e}")
            return False
    
    async def _scan_domain(self, domain: str, scan_type: str) -> Optional[ScanResult]:
        """Run ZAP scan for a single domain"""
        try:
            # Use the DAST monitor's scan method
            result = await self._run_zap_scan(domain, scan_type)
            return result
            
        except Exception as e:
            self.logger.error(f"ZAP scan failed for {domain}: {e}")
            return None
    
    async def _run_zap_scan(self, target_url: str, scan_type: str) -> ScanResult:
        """Execute ZAP scan using Docker container"""
        start_time = datetime.now()
        
        try:
            # This is a simplified implementation - in reality you'd run ZAP Docker container
            self.logger.info(f"Starting ZAP scan for {target_url} (type: {scan_type})")
            
            # Simulate scan execution (replace with actual ZAP Docker command)
            await asyncio.sleep(5)  # Simulate scan time
            
            # Create mock result (replace with actual ZAP report parsing)
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            result = ScanResult(
                target=target_url,
                timestamp=end_time,
                scan_type=scan_type,
                duration=duration,
                alerts_high=0,
                alerts_medium=1,
                alerts_low=2,
                alerts_info=1,
                total_alerts=4,
                status='completed'
            )
            
            self.logger.info(f"Scan completed for {target_url} in {duration:.1f}s")
            return result
            
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            result = ScanResult(
                target=target_url,
                timestamp=end_time,
                scan_type=scan_type,
                duration=duration,
                alerts_high=0,
                alerts_medium=0,
                alerts_low=0,
                alerts_info=0,
                total_alerts=0,
                status='failed'
            )
            
            self.logger.error(f"Scan failed for {target_url}: {e}")
            return result
    
    async def _process_scan_results(self, target: ScanTarget, results: List[ScanResult]):
        """Process and store scan results"""
        try:
            for result in results:
                # Store result in database
                self.monitor._store_scan_result(result)
                
                # Send notifications if needed
                await self._send_notifications(result)
            
            self.logger.info(f"Processed {len(results)} scan results for {target.domain}")
            
        except Exception as e:
            self.logger.error(f"Failed to process scan results: {e}")
    
    async def _send_notifications(self, result: ScanResult):
        """Send notifications for scan results"""
        try:
            # Only send notifications for significant findings
            if result.alerts_high > 0 or result.alerts_medium > 3:
                await self.monitor._send_notifications(result)
                self.logger.info(f"Notifications sent for {result.target}")
                
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {e}")
    
    async def _check_maintenance(self):
        """Check if maintenance tasks need to be run"""
        current_time = datetime.now()
        
        if (current_time - self.last_maintenance).total_seconds() >= self.maintenance_interval:
            self.logger.info("Running maintenance tasks...")
            
            try:
                await self.monitor._run_maintenance()
                self.last_maintenance = current_time
                self.logger.info("Maintenance tasks completed")
                
            except Exception as e:
                self.logger.error(f"Maintenance tasks failed: {e}")
    
    async def stop(self):
        """Stop the daemon gracefully"""
        self.logger.info("Stopping DAST Monitor Daemon...")
        self.running = False
        
        if self.monitor:
            # Save current state
            await self._save_state()
        
        self.logger.info("Daemon stopped successfully")
    
    async def _save_state(self):
        """Save current monitoring state"""
        try:
            state = {
                'last_maintenance': self.last_maintenance.isoformat() if self.last_maintenance else None,
                'targets': [
                    {
                        'domain': target.domain,
                        'last_scan': target.last_scan.isoformat() if target.last_scan else None,
                        'next_scan': target.next_scan.isoformat() if target.next_scan else None,
                        'priority': target.priority
                    }
                    for target in self.monitor.targets
                ]
            }
            
            state_file = Path('data/daemon_state.json')
            state_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            self.logger.info(f"State saved to {state_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")


async def main():
    """Main daemon entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DAST Monitor Daemon - Continuous Security Scanning")
    parser.add_argument("--config", default="config/dast_config.yaml", help="Configuration file path")
    parser.add_argument("--check-interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("--maintenance-interval", type=int, default=3600, help="Maintenance interval in seconds")
    
    args = parser.parse_args()
    
    daemon = MonitorDaemon(args.config)
    daemon.check_interval = args.check_interval
    daemon.maintenance_interval = args.maintenance_interval
    
    try:
        await daemon.start()
    except KeyboardInterrupt:
        print("\nReceived interrupt signal")
    except Exception as e:
        print(f"Daemon failed: {e}")
        sys.exit(1)
    finally:
        await daemon.stop()


if __name__ == "__main__":
    # Ensure required directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    
    # Run the daemon
    asyncio.run(main())