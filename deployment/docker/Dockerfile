# Multi-stage Dockerfile for DAST Monitor
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set working directory
WORKDIR /app

# Create non-root user
RUN groupadd -r dast && useradd -r -g dast -s /bin/bash dast

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    dnsutils \
    net-tools \
    docker.io \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install subdomain discovery tools
RUN wget -qO- https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_*_linux_amd64.tar.gz | tar -xzf - -C /usr/local/bin/ subfinder && \
    wget -qO- https://github.com/tomnomnom/assetfinder/releases/latest/download/assetfinder-linux-amd64-*.tgz | tar -xzf - -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/assetfinder

# Optional: Install additional tools
RUN wget -qO /usr/local/bin/amass https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64 && \
    chmod +x /usr/local/bin/amass || echo "Amass installation failed, continuing..."

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/reports /app/logs /app/data /app/config && \
    chown -R dast:dast /app

# Set permissions for Docker socket access
RUN usermod -aG docker dast

# Switch to non-root user
USER dast

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 9090

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO

# Default command
CMD ["python", "dast_monitor.py"]