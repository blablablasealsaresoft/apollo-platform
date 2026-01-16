# Apollo Custom Metrics Exporter Dockerfile
FROM python:3.11-slim

LABEL maintainer="Apollo Platform Team"
LABEL description="Custom metrics exporter for Apollo Platform"

# Create non-root user
RUN groupadd -r apollo && useradd -r -g apollo apollo

WORKDIR /app

# Copy application
COPY apollo-metrics-exporter.py .

# Set permissions
RUN chown -R apollo:apollo /app

# Switch to non-root user
USER apollo

# Expose metrics port
EXPOSE 9101

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9101/health')" || exit 1

# Run the exporter
CMD ["python", "-u", "apollo-metrics-exporter.py"]
