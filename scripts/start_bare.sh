#!/bin/bash

# DAST Monitor - Bare Version Startup Script
# This script starts the minimal DAST monitoring without Grafana, Prometheus, Redis

set -e

echo "Starting DAST Monitor - Bare Version"
echo "===================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Set default environment variables if not provided
export GOOGLE_WORKSPACE_WEBHOOK_URL=${GOOGLE_WORKSPACE_WEBHOOK_URL:-""}
export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-"secure-password-change-me"}
export ADMIN_API_TOKEN=${ADMIN_API_TOKEN:-"admin-token-change-me"}
export READONLY_API_TOKEN=${READONLY_API_TOKEN:-"readonly-token-change-me"}
export RETENTION_DAYS=${RETENTION_DAYS:-"90"}

# Create necessary directories
echo "Creating directories..."
mkdir -p deployment/docker/reports
mkdir -p deployment/docker/logs
mkdir -p deployment/docker/data

# Check if configuration file exists
if [ ! -f "config/dast_config.yaml" ]; then
    echo "Error: config/dast_config.yaml not found"
    echo "Please ensure the configuration file is in the correct location."
    exit 1
fi

# Navigate to deployment directory
cd deployment/docker

# Validate required environment variables
if [ -z "$GOOGLE_WORKSPACE_WEBHOOK_URL" ]; then
    echo "Warning: GOOGLE_WORKSPACE_WEBHOOK_URL not set. Notifications will be disabled."
    echo "To enable Google Workspace notifications, set:"
    echo "export GOOGLE_WORKSPACE_WEBHOOK_URL='https://chat.googleapis.com/v1/spaces/.../messages?key=...'"
fi

echo "Starting services with Docker Compose..."
echo "Using configuration: config/dast_config.yaml"
echo ""

# Start the bare version services
docker-compose up -d

echo ""
echo "Waiting for services to start..."
sleep 10

# Check service health
echo "Checking service status..."
docker-compose ps

echo ""
echo "DAST Monitor - Bare Version Started Successfully!"
echo "============================================="
echo ""
echo "Services running:"
echo "- DAST Monitor API: http://localhost:8080"
echo "- PostgreSQL: localhost:5432"
echo ""
echo "Available endpoints:"
echo "- Health check: http://localhost:8080/health"
echo "- API documentation: http://localhost:8080/docs"
echo ""
echo "To view logs:"
echo "docker-compose logs -f dast-monitor"
echo ""
echo "To stop services:"
echo "docker-compose down"
echo ""

# Optional: Show recent logs
echo "Recent logs from DAST Monitor:"
echo "=============================="
docker-compose logs --tail=10 dast-monitor

echo ""
echo "Setup complete!"