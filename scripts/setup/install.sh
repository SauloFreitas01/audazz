#!/bin/bash
# DAST Monitor - Bare Version Installation Script

set -e

echo "DAST Monitor - Bare Version Installation"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is required but not installed. Please install Docker first."
    fi
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        error "Docker Compose V2 is required but not available. Please install Docker Compose V2."
    fi
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        warning "Python 3 is recommended for running maintenance scripts"
    fi
    
    success "System requirements check passed"
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    # Core directories
    if ! mkdir -p data logs reports; then
        error "Failed to create core directories"
    fi
    
    # Docker deployment directories
    if ! mkdir -p deployment/docker/{data,logs,reports}; then
        error "Failed to create Docker directories"
    fi
    
    success "Directory structure created"
}

# Setup configuration
setup_config() {
    log "Setting up configuration..."
    
    # Check if config file exists
    if [[ ! -f "config/dast_config.yaml" ]]; then
        error "Configuration file config/dast_config.yaml not found"
    fi
    
    # Create environment file template
    cat > .env.example << 'EOF'
# Google Workspace Webhook (Primary notification method)
GOOGLE_WORKSPACE_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/YOUR_SPACE/messages?key=YOUR_KEY

# Database (optional - can use file-based storage)
POSTGRES_PASSWORD=secure-password-change-me

# API Security
ADMIN_API_TOKEN=admin-token-change-me
READONLY_API_TOKEN=readonly-token-change-me

# Data retention
RETENTION_DAYS=90

# Backup notification methods
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
EOF

    if [[ ! -f ".env" ]]; then
        cp .env.example .env
        warning "Created .env file from template. Please update with your values."
    fi
    
    success "Configuration setup completed"
}

# Build and start services
start_services() {
    log "Building and starting services..."
    
    cd deployment/docker
    
    # Build the application
    if ! docker compose build; then
        error "Failed to build Docker images"
    fi
    
    # Start core services
    if ! docker compose up -d; then
        error "Failed to start services"
    fi
    
    cd ../..
    
    success "Services started successfully"
}

# Wait for services to be ready
wait_for_services() {
    log "Waiting for services to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:8080/health > /dev/null 2>&1; then
            success "Services are ready"
            return 0
        fi
        
        log "Attempt $attempt/$max_attempts - Waiting for services..."
        sleep 10
        ((attempt++))
    done
    
    error "Services failed to start within expected time"
}

# Display installation summary
show_summary() {
    echo ""
    echo "========================================="
    echo "DAST Monitor - Bare Version Installation Complete!"
    echo "========================================="
    echo ""
    echo "Services running:"
    echo "- DAST Monitor API: http://localhost:8080"
    echo "- PostgreSQL: localhost:5432 (if enabled)"
    echo ""
    echo "Quick start:"
    echo "1. Update .env file with your Google Workspace webhook URL"
    echo "2. Test the installation:"
    echo "   python3 scripts/maintenance/process_zap_metrics.py --summary"
    echo ""
    echo "Management commands:"
    echo "- View logs: docker compose -f deployment/docker/docker-compose.yml logs -f"
    echo "- Stop services: docker compose -f deployment/docker/docker-compose.yml down"
    echo "- Restart services: docker compose -f deployment/docker/docker-compose.yml restart"
    echo ""
    echo "For detailed documentation, see README_BARE.md"
    echo ""
}

# Main installation flow
main() {
    log "Starting DAST Monitor - Bare Version installation..."
    
    check_root
    check_requirements
    create_directories
    setup_config
    start_services
    wait_for_services
    show_summary
    
    success "Installation completed successfully!"
}

# Run installation
main "$@"