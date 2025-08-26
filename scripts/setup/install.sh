#!/bin/bash
# DAST Monitor Installation Script

set -e

echo "🚀 DAST Monitor Installation Script"
echo "=================================="

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
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is required but not installed."
    fi
    
    # Check available disk space (minimum 10GB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [ $available_space -lt 10485760 ]; then  # 10GB in KB
        warning "Less than 10GB free space available. Consider freeing up disk space."
    fi
    
    # Check available memory (minimum 4GB)
    total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_mem -lt 4096 ]; then
        warning "Less than 4GB RAM available. Performance may be impacted."
    fi
    
    success "System requirements check completed"
}

# Install subdomain discovery tools
install_subdomain_tools() {
    log "Installing subdomain discovery tools..."
    
    # Create tools directory
    mkdir -p ./tools
    
    # Install subfinder
    if ! command -v subfinder &> /dev/null; then
        log "Installing subfinder..."
        wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.zip -O subfinder.zip
        unzip -q subfinder.zip
        sudo mv subfinder /usr/local/bin/
        rm subfinder.zip README.md LICENSE.md
    fi
    
    # Install assetfinder
    if ! command -v assetfinder &> /dev/null; then
        log "Installing assetfinder..."
        wget -q https://github.com/tomnomnom/assetfinder/releases/latest/download/assetfinder-linux-amd64-1.0.0.tgz -O assetfinder.tgz
        tar -xzf assetfinder.tgz
        sudo mv assetfinder /usr/local/bin/
        rm assetfinder.tgz
    fi
    
    # Install amass (optional)
    if ! command -v amass &> /dev/null; then
        log "Installing amass..."
        wget -q https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -O amass.zip
        unzip -q amass.zip -d amass_tmp
        sudo mv amass_tmp/amass_linux_amd64/amass /usr/local/bin/
        rm -rf amass.zip amass_tmp
    fi
    
    success "Subdomain discovery tools installed"
}

# Setup directories and permissions
setup_directories() {
    log "Setting up directories and permissions..."
    
    # Create necessary directories
    mkdir -p data/{reports,logs,exports}
    mkdir -p security/certificates
    mkdir -p config/{grafana,prometheus,nginx}
    
    # Set proper permissions
    chmod 755 data/
    chmod 755 data/{reports,logs,exports}
    chmod 700 security/certificates
    
    # Create .gitkeep files
    touch data/reports/.gitkeep
    touch data/logs/.gitkeep
    touch security/certificates/.gitkeep
    
    success "Directories created and permissions set"
}

# Setup environment file
setup_environment() {
    log "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            warning "Created .env from example. Please customize it with your settings."
        else
            error ".env.example file not found"
        fi
    else
        log ".env file already exists, skipping creation"
    fi
    
    # Generate secure tokens if needed
    if grep -q "change-me" .env; then
        warning "Default tokens found in .env file. Consider updating them for security."
        log "You can generate secure tokens with: openssl rand -hex 32"
    fi
    
    success "Environment configuration ready"
}

# Pull required Docker images
pull_images() {
    log "Pulling required Docker images..."
    
    docker-compose -f deployment/docker/docker-compose.yml pull
    
    success "Docker images pulled successfully"
}

# Initialize database
init_database() {
    log "Initializing database..."
    
    # Start only database services
    docker-compose -f deployment/docker/docker-compose.yml up -d postgres redis
    
    # Wait for services to be ready
    log "Waiting for database services to be ready..."
    sleep 30
    
    # Run database migrations (if any)
    # docker-compose -f deployment/docker/docker-compose.yml exec dast-monitor python -m alembic upgrade head
    
    success "Database initialized"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring and dashboards..."
    
    # Start Grafana and Prometheus
    docker-compose -f deployment/docker/docker-compose.yml up -d grafana prometheus
    
    # Wait for Grafana to be ready
    sleep 30
    
    log "Grafana dashboard: http://localhost:3000"
    log "Default credentials: admin / admin-change-me"
    
    success "Monitoring setup completed"
}

# Main installation function
main() {
    echo
    log "Starting DAST Monitor installation..."
    echo
    
    check_root
    check_requirements
    install_subdomain_tools
    setup_directories
    setup_environment
    pull_images
    init_database
    setup_monitoring
    
    echo
    success "🎉 DAST Monitor installation completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Customize your .env file with your specific configuration"
    echo "2. Start the full system: docker-compose -f deployment/docker/docker-compose.yml up -d"
    echo "3. Add your first target: python main.py --add-target yourapp.com"
    echo "4. Access Grafana dashboard at http://localhost:3000"
    echo "5. Check the README.md for detailed usage instructions"
    echo
    log "Installation completed at $(date)"
}

# Run main function
main "$@"