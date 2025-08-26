#!/usr/bin/env python3
"""
DAST Continuous Monitoring System - Main Entry Point
"""

import sys
import os
import argparse
import asyncio
from pathlib import Path

# Add app directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from core.dast_monitor import DASTMonitor

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='DAST Continuous Monitoring System')
    parser.add_argument('--config', default='config/dast_config.yaml', 
                       help='Configuration file path')
    parser.add_argument('--add-target', help='Add a target domain')
    parser.add_argument('--scan-type', default='standard', 
                       choices=['standard', 'spa', 'api'], 
                       help='Scan type for new targets')
    parser.add_argument('--priority', type=int, default=1, choices=[1,2,3,4,5],
                       help='Priority level (1-5, higher = more frequent)')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--daemon', action='store_true', 
                       help='Run in daemon mode (continuous monitoring)')
    
    args = parser.parse_args()
    
    # Ensure we're running from the correct directory
    os.chdir(Path(__file__).parent)
    
    monitor = DASTMonitor(args.config)
    
    try:
        if args.add_target:
            monitor.add_target(args.add_target, args.scan_type, args.priority)
            print(f"✓ Added target: {args.add_target}")
        elif args.status:
            status = monitor.get_status()
            print("DAST Monitor Status:")
            print(f"  Status: {status['status']}")
            print(f"  Targets: {status['targets']}")
            print(f"  Recent scans (24h): {status['recent_scans_24h']}")
            print(f"  Avg alerts (24h): {status['avg_alerts_24h']:.1f}")
            print(f"  Next scan: {status['next_scheduled_scan']}")
        else:
            print("🚀 Starting DAST Continuous Monitor...")
            monitor.start()
    except KeyboardInterrupt:
        print("\n⏹️  Shutting down gracefully...")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()