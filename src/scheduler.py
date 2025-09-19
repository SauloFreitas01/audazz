import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Callable, Optional
import schedule


logger = logging.getLogger(__name__)


class ScanScheduler:
    def __init__(self, scan_function: Callable[[str, str], Dict[str, Any]]):
        self.scan_function = scan_function
        self.is_running = False
        self.scheduler_thread = None
        self.manual_scan_lock = threading.Lock()
        self.scheduled_jobs = {}

    def start(self):
        """Start the scheduler in a separate thread."""
        if self.is_running:
            logger.warning("Scheduler is already running")
            return

        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        logger.info("Scan scheduler started")

    def stop(self):
        """Stop the scheduler."""
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Scan scheduler stopped")

    def _run_scheduler(self):
        """Main scheduler loop."""
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(60)

    def schedule_target(self, target_name: str, target_url: str, interval_hours: int,
                       scan_policy: str = "default"):
        """Schedule periodic scans for a target."""
        job_id = f"{target_name}_periodic"

        # Remove existing job if it exists
        if job_id in self.scheduled_jobs:
            schedule.cancel_job(self.scheduled_jobs[job_id])

        # Create new job
        job = schedule.every(interval_hours).hours.do(
            self._execute_scheduled_scan,
            target_name=target_name,
            target_url=target_url,
            scan_policy=scan_policy
        )

        self.scheduled_jobs[job_id] = job
        logger.info(f"Scheduled periodic scan for {target_name} every {interval_hours} hours")

    def unschedule_target(self, target_name: str):
        """Remove scheduled scans for a target."""
        job_id = f"{target_name}_periodic"
        if job_id in self.scheduled_jobs:
            schedule.cancel_job(self.scheduled_jobs[job_id])
            del self.scheduled_jobs[job_id]
            logger.info(f"Unscheduled periodic scan for {target_name}")

    def _execute_scheduled_scan(self, target_name: str, target_url: str, scan_policy: str):
        """Execute a scheduled scan."""
        logger.info(f"Starting scheduled scan for {target_name}")

        try:
            # Check if manual scan is running
            if not self.manual_scan_lock.acquire(blocking=False):
                logger.warning(f"Skipping scheduled scan for {target_name} - manual scan in progress")
                return

            try:
                result = self.scan_function(target_url, scan_policy)
                logger.info(f"Scheduled scan completed for {target_name}")
                return result
            finally:
                self.manual_scan_lock.release()

        except Exception as e:
            logger.error(f"Scheduled scan failed for {target_name}: {e}")

    def execute_manual_scan(self, target_name: str, target_url: str,
                          scan_policy: str = "default") -> Optional[Dict[str, Any]]:
        """Execute a manual scan without interfering with scheduled scans."""
        logger.info(f"Starting manual scan for {target_name}")

        # Acquire lock to prevent conflicts with scheduled scans
        with self.manual_scan_lock:
            try:
                result = self.scan_function(target_url, scan_policy)
                logger.info(f"Manual scan completed for {target_name}")
                return result
            except Exception as e:
                logger.error(f"Manual scan failed for {target_name}: {e}")
                raise

    def get_next_scan_times(self) -> Dict[str, str]:
        """Get next scheduled scan times for all targets."""
        next_runs = {}

        for job_id, job in self.scheduled_jobs.items():
            target_name = job_id.replace("_periodic", "")
            if job.next_run:
                next_runs[target_name] = job.next_run.strftime("%Y-%m-%d %H:%M:%S")
            else:
                next_runs[target_name] = "Not scheduled"

        return next_runs

    def get_scheduler_status(self) -> Dict[str, Any]:
        """Get current scheduler status."""
        return {
            "is_running": self.is_running,
            "scheduled_targets": len(self.scheduled_jobs),
            "next_scan_times": self.get_next_scan_times(),
            "manual_scan_in_progress": not self.manual_scan_lock.acquire(blocking=False)
        }