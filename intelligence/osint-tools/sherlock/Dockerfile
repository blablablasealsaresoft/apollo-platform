# Sherlock OSINT - Docker Image
# Production-ready container for username search operations

FROM python:3.11-slim

LABEL maintainer="Apollo Intelligence Platform"
LABEL description="Sherlock OSINT - Username search across 400+ platforms"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p /app/exports /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SHERLOCK_ENV=production

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Default command (run FastAPI server)
CMD ["python", "fastapi_endpoints.py"]
