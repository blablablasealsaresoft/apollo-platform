FROM python:3.11-slim

# WARNING: This container includes offensive security tools
# AUTHORIZED USE ONLY

LABEL maintainer="Apollo Red Team Platform"
LABEL description="Red Team Operations Container - AUTHORIZED USE ONLY"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    git \
    curl \
    wget \
    build-essential \
    libpcap-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app/redteam

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /app/redteam/data/authorizations \
    /app/redteam/data/audit-logs \
    /app/redteam/data/bbot-scans \
    /app/redteam/reports

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Display legal disclaimer on startup
CMD echo "╔════════════════════════════════════════════════════════════╗" && \
    echo "║  APOLLO RED TEAM PLATFORM - AUTHORIZED USE ONLY            ║" && \
    echo "║  All operations are logged and monitored                   ║" && \
    echo "║  Unauthorized use is ILLEGAL                               ║" && \
    echo "╚════════════════════════════════════════════════════════════╝" && \
    python orchestration/api_server.py
