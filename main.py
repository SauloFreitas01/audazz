#!/usr/bin/env python3
import argparse
import sys
import time
import uvicorn
from src.autodast import AutoDast
from src.api import app


def run_daemon_mode():
    """Run AutoDast in daemon mode (monitoring only)."""
    print("Starting AutoDast in daemon mode...")

    autodast = AutoDast()

    if not autodast.start():
        print("Failed to start AutoDast")
        sys.exit(1)

    try:
        print("AutoDast is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nShutting down AutoDast...")
        autodast.stop()


def run_api_mode(host: str = "0.0.0.0", port: int = 8000):
    """Run AutoDast with web API interface."""
    print(f"Starting AutoDast API server on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


def run_manual_scan(target_input: str, scan_policy: str = None):
    """Run a single manual scan."""

    autodast = AutoDast()

    # Determine if target_input is a name or URL
    if target_input.startswith(('http://', 'https://')):
        # target_input is a URL
        target_url = target_input
        target_name = url_to_target_name(target_url)
        print(f"Running manual scan for URL: {target_url} (target name: {target_name})")
    else:
        # target_input is a target name
        target_name = target_input
        target_url = None
        print(f"Running manual scan for target: {target_name}")

    try:
        result = autodast.execute_manual_scan(target_name, scan_policy, target_url)

        if result.get("success"):
            print(f"Scan completed successfully for {target_name}")

            # Show if target was added
            if result.get("target_added"):
                print(f"Target '{target_name}' was added to configuration")

            scan_result = result["scan_result"]
            summary = scan_result.get("summary", {})
            print(f"Vulnerabilities found: High({summary.get('High', 0)}), "
                  f"Medium({summary.get('Medium', 0)}), "
                  f"Low({summary.get('Low', 0)}), "
                  f"Info({summary.get('Informational', 0)})")

            if "report_files" in result:
                print("Reports generated:")
                for format_type, filepath in result["report_files"].items():
                    print(f"  {format_type.upper()}: {filepath}")
        else:
            print(f"Scan failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)

    except Exception as e:
        print(f"Error running manual scan: {e}")
        sys.exit(1)


def url_to_target_name(url: str) -> str:
    """Convert URL to a target name."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc
    # Remove common prefixes and create a clean name
    name = hostname.replace('www.', '').replace('-', '_')
    return name


def show_status():
    """Show system status."""
    try:
        autodast = AutoDast()
        status = autodast.get_system_status()
        targets_status = autodast.get_target_status()

        print("=== AutoDast System Status ===")
        print(f"ZAP Available: {status['zap_available']}")
        print(f"Targets Configured: {status['targets_count']}")
        print(f"Webhook Configured: {status['webhook_configured']}")

        # Show ZAP status details
        zap_status = status.get('zap_status', {})
        print(f"\n=== ZAP Status ===")
        print(f"Mode: {zap_status.get('mode', 'unknown')}")
        print(f"Using Docker: {zap_status.get('using_docker', False)}")
        if zap_status.get('version'):
            print(f"Version: {zap_status.get('version')}")

        if zap_status.get('container'):
            container = zap_status['container']
            print(f"Container Status: {container.get('status', 'unknown')}")
            print(f"Container ID: {container.get('id', 'unknown')}")

        print("\n=== Scheduler Status ===")
        scheduler_status = targets_status.get("scheduler", {})
        print(f"Running: {scheduler_status.get('is_running', False)}")
        print(f"Scheduled Targets: {scheduler_status.get('scheduled_targets', 0)}")

        next_scans = scheduler_status.get('next_scan_times', {})
        if next_scans:
            print("\n=== Next Scheduled Scans ===")
            for target, next_time in next_scans.items():
                print(f"{target}: {next_time}")

        targets = targets_status.get("targets", {})
        if targets:
            print("\n=== Target Statistics ===")
            for target_name, target_data in targets.items():
                stats = target_data.get("stats", {})
                print(f"\n{target_name}:")
                print(f"  Total Scans: {stats.get('total_scans', 0)}")
                print(f"  Last Scan: {stats.get('last_scan', 'Never')}")

                last_vulns = stats.get('last_vulnerabilities', {})
                if last_vulns:
                    print(f"  Last Vulnerabilities: High({last_vulns.get('high', 0)}), "
                          f"Medium({last_vulns.get('medium', 0)}), "
                          f"Low({last_vulns.get('low', 0)}), "
                          f"Info({last_vulns.get('informational', 0)})")

    except Exception as e:
        print(f"Error getting status: {e}")
        sys.exit(1)


def test_webhook():
    """Test Google Chat webhook."""
    try:
        autodast = AutoDast()
        success = autodast.test_google_chat_webhook()

        if success:
            print("✅ Webhook test successful!")
        else:
            print("❌ Webhook test failed!")
            sys.exit(1)

    except Exception as e:
        print(f"Error testing webhook: {e}")
        sys.exit(1)


def start_zap():
    """Start ZAP container (Docker mode only)."""
    try:
        autodast = AutoDast()
        if not autodast.zap_client.using_docker:
            print("❌ ZAP Docker mode is not enabled in configuration")
            sys.exit(1)

        print("Starting ZAP Docker container...")
        success = autodast.zap_client.start_zap()

        if success:
            print("ZAP container started successfully!")
        else:
            print("Failed to start ZAP container!")
            sys.exit(1)

    except Exception as e:
        print(f"Error starting ZAP container: {e}")
        sys.exit(1)


def stop_zap():
    """Stop ZAP container (Docker mode only)."""
    try:
        autodast = AutoDast()
        if not autodast.zap_client.using_docker:
            print("❌ ZAP Docker mode is not enabled in configuration")
            sys.exit(1)

        print("Stopping ZAP Docker container...")
        success = autodast.zap_client.stop_zap()

        if success:
            print("ZAP container stopped successfully!")
        else:
            print("Failed to stop ZAP container!")
            sys.exit(1)

    except Exception as e:
        print(f"Error stopping ZAP container: {e}")
        sys.exit(1)


def restart_zap():
    """Restart ZAP container (Docker mode only)."""
    try:
        autodast = AutoDast()
        if not autodast.zap_client.using_docker:
            print("❌ ZAP Docker mode is not enabled in configuration")
            sys.exit(1)

        print("Restarting ZAP Docker container...")
        success = autodast.restart_zap()

        if success:
            print("ZAP container restarted successfully!")
        else:
            print("Failed to restart ZAP container!")
            sys.exit(1)

    except Exception as e:
        print(f"Error restarting ZAP container: {e}")
        sys.exit(1)


def show_zap_logs():
    """Show ZAP container logs (Docker mode only)."""
    try:
        autodast = AutoDast()
        if not autodast.zap_client.using_docker:
            print("❌ ZAP Docker mode is not enabled in configuration")
            sys.exit(1)

        print("=== ZAP Container Logs ===")
        logs = autodast.get_zap_logs()
        print(logs)

    except Exception as e:
        print(f"Error getting ZAP logs: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AutoDast - Automated Web Application Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s daemon                         # Run in daemon mode (monitoring)
  %(prog)s api                            # Run with web API interface
  %(prog)s scan myapp                     # Run manual scan for 'myapp' target
  %(prog)s scan myapp --policy quick      # Run manual scan with 'quick' policy
  %(prog)s scan https://example.com       # Scan URL (auto-creates target)
  %(prog)s scan https://test.com --policy comprehensive  # Scan URL with policy
  %(prog)s status                         # Show system status
  %(prog)s test-webhook                   # Test Google Chat webhook
  %(prog)s start-zap                      # Start ZAP Docker container
  %(prog)s stop-zap                       # Stop ZAP Docker container
  %(prog)s restart-zap                    # Restart ZAP Docker container
  %(prog)s zap-logs                       # Show ZAP container logs
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Daemon mode
    daemon_parser = subparsers.add_parser('daemon', help='Run in daemon mode')

    # API mode
    api_parser = subparsers.add_parser('api', help='Run with web API interface')
    api_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    api_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')

    # Manual scan
    scan_parser = subparsers.add_parser('scan', help='Run manual scan')
    scan_parser.add_argument('target', help='Target name or URL to scan')
    scan_parser.add_argument('--policy', help='Scan policy to use')

    # Status
    status_parser = subparsers.add_parser('status', help='Show system status')

    # Test webhook
    webhook_parser = subparsers.add_parser('test-webhook', help='Test Google Chat webhook')

    # ZAP Docker commands
    start_zap_parser = subparsers.add_parser('start-zap', help='Start ZAP Docker container')
    stop_zap_parser = subparsers.add_parser('stop-zap', help='Stop ZAP Docker container')
    restart_zap_parser = subparsers.add_parser('restart-zap', help='Restart ZAP Docker container')
    zap_logs_parser = subparsers.add_parser('zap-logs', help='Show ZAP container logs')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'daemon':
        run_daemon_mode()
    elif args.command == 'api':
        run_api_mode(args.host, args.port)
    elif args.command == 'scan':
        run_manual_scan(args.target, args.policy)
    elif args.command == 'status':
        show_status()
    elif args.command == 'test-webhook':
        test_webhook()
    elif args.command == 'start-zap':
        start_zap()
    elif args.command == 'stop-zap':
        stop_zap()
    elif args.command == 'restart-zap':
        restart_zap()
    elif args.command == 'zap-logs':
        show_zap_logs()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()