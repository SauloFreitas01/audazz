#!/bin/bash



set -e

DAEMON_NAME="autoDAST-daemon"
DAEMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON_SCRIPT="app/daemon/monitor_daemon.py"
PID_FILE="data/daemon.pid"
LOG_FILE="logs/daemon_control.log"
CONFIG_FILE="config/dast_config.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Ensure we're in the correct directory
cd "$DAEMON_DIR"

# Create necessary directories
mkdir -p data logs

check_dependencies() {
    log "Checking dependencies..."
    
    if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
        error "Python 3 is required but not found"
        exit 1
    fi
    
    # Try python first, then python3
    PYTHON_CMD="python"
    if ! command -v python &> /dev/null; then
        PYTHON_CMD="python3"
    fi
    
    if ! $PYTHON_CMD -c "import asyncio, yaml, sqlite3" 2>/dev/null; then
        error "Required Python modules not found. Install with: pip install pyyaml"
        exit 1
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    success "Dependencies check passed"
}

is_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            return 0
        else
            # PID file exists but process is dead
            rm -f "$PID_FILE"
            return 1
        fi
    fi
    return 1
}

get_status() {
    if is_running; then
        local pid=$(cat "$PID_FILE")
        echo "running (PID: $pid)"
    else
        echo "stopped"
    fi
}

start_daemon() {
    log "Starting $DAEMON_NAME..."
    
    if is_running; then
        warning "Daemon is already running (PID: $(cat "$PID_FILE"))"
        return 0
    fi
    
    check_dependencies
    
    # Start the daemon in background
    nohup $PYTHON_CMD "$DAEMON_SCRIPT" --config "$CONFIG_FILE" > "logs/daemon_stdout.log" 2>&1 &
    local daemon_pid=$!
    
    # Save PID
    echo "$daemon_pid" > "$PID_FILE"
    
    # Wait a moment to check if it started successfully
    sleep 2
    
    if is_running; then
        success "Daemon started successfully (PID: $daemon_pid)"
        log "Logs: tail -f logs/monitor_daemon.log"
        log "Control: $0 {start|stop|restart|status|logs}"
    else
        error "Failed to start daemon"
        rm -f "$PID_FILE"
        exit 1
    fi
}

stop_daemon() {
    log "Stopping $DAEMON_NAME..."
    
    if ! is_running; then
        warning "Daemon is not running"
        return 0
    fi
    
    local pid=$(cat "$PID_FILE")
    
    # Send SIGTERM for graceful shutdown
    kill -TERM "$pid" 2>/dev/null || true
    
    # Wait for graceful shutdown
    local count=0
    while [ $count -lt 10 ] && is_running; do
        sleep 1
        count=$((count + 1))
    done
    
    # Force kill if still running
    if is_running; then
        warning "Daemon not responding, forcing shutdown..."
        kill -KILL "$pid" 2>/dev/null || true
        sleep 1
    fi
    
    # Clean up PID file
    rm -f "$PID_FILE"
    
    if ! is_running; then
        success "Daemon stopped successfully"
    else
        error "Failed to stop daemon"
        exit 1
    fi
}

restart_daemon() {
    log "Restarting $DAEMON_NAME..."
    stop_daemon
    sleep 2
    start_daemon
}

show_status() {
    local status=$(get_status)
    log "Daemon status: $status"
    
    if is_running; then
        local pid=$(cat "$PID_FILE")
        local uptime=$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ' || echo "unknown")
        log "Uptime: $uptime"
        log "Memory usage: $(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo "unknown") KB"
    fi
    
    # Show recent log entries
    if [ -f "logs/monitor_daemon.log" ]; then
        log "Recent log entries:"
        tail -5 "logs/monitor_daemon.log" | while read line; do
            echo "  $line"
        done
    fi
}

show_logs() {
    if [ -f "logs/monitor_daemon.log" ]; then
        log "Following daemon logs (Ctrl+C to exit):"
        tail -f "logs/monitor_daemon.log"
    else
        warning "Log file not found: logs/monitor_daemon.log"
    fi
}

add_target() {
    local domain="$1"
    local priority="${2:-2}"
    
    if [ -z "$domain" ]; then
        error "Usage: $0 add-target <domain> [priority]"
        exit 1
    fi
    
    log "Adding target: $domain (priority: $priority)"
    
    # Use the ZAP metrics processor to add the target
    $PYTHON_CMD scripts/maintenance/process_zap_metrics.py --domain "$domain" --summary
    
    success "Target added. The daemon will pick it up on the next cycle."
}

remove_target() {
    local domain="$1"
    
    if [ -z "$domain" ]; then
        error "Usage: $0 remove-target <domain>"
        exit 1
    fi
    
    log "Removing target: $domain"
    
    # Remove from database (simplified - in reality you'd want a proper API)
    $PYTHON_CMD -c "
import sqlite3
conn = sqlite3.connect('data/db/dast_monitor.db')
cursor = conn.cursor()
cursor.execute('DELETE FROM targets WHERE domain = ?', ('$domain',))
conn.commit()
conn.close()
print('Target removed from database')
"
    
    success "Target $domain removed. Restart daemon to apply changes."
}

list_targets() {
    log "Listing monitored targets:"
    
    $PYTHON_CMD -c "
import sqlite3
import json
from datetime import datetime

try:
    conn = sqlite3.connect('data/db/dast_monitor.db')
    cursor = conn.cursor()
    cursor.execute('SELECT domain, priority, last_scan, next_scan FROM targets ORDER BY priority DESC, domain')
    targets = cursor.fetchall()
    conn.close()
    
    if not targets:
        print('No targets configured')
    else:
        print(f\"{'Domain':<30} {'Priority':<8} {'Last Scan':<20} {'Next Scan':<20}\")
        print('-' * 80)
        for domain, priority, last_scan, next_scan in targets:
            last = last_scan[:19] if last_scan else 'Never'
            next_time = next_scan[:19] if next_scan else 'Not scheduled'
            print(f\"{domain:<30} {priority:<8} {last:<20} {next_time:<20}\")
except Exception as e:
    print(f'Error: {e}')
"
}

show_help() {
    echo "DAST Monitor Daemon Control Script"
    echo "=================================="
    echo ""
    echo "Usage: $0 {command} [options]"
    echo ""
    echo "Commands:"
    echo "  start                Start the monitoring daemon"
    echo "  stop                 Stop the monitoring daemon"
    echo "  restart              Restart the monitoring daemon"
    echo "  status               Show daemon status and recent logs"
    echo "  logs                 Follow daemon logs in real-time"
    echo "  add-target <domain> [priority]  Add a domain to monitor"
    echo "  remove-target <domain>          Remove a domain from monitoring"
    echo "  list-targets         List all monitored targets"
    echo "  help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 add-target example.com 3"
    echo "  $0 status"
    echo "  $0 logs"
    echo ""
}

# Set Python command globally
PYTHON_CMD="python"
if ! command -v python &> /dev/null; then
    PYTHON_CMD="python3"
fi

# Main command handling
case "${1:-}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        restart_daemon
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    add-target)
        add_target "$2" "$3"
        ;;
    remove-target)
        remove_target "$2"
        ;;
    list-targets)
        list_targets
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|add-target|remove-target|list-targets|help}"
        echo "Run '$0 help' for detailed usage information"
        exit 1
        ;;
esac