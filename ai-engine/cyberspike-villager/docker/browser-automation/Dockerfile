FROM selenium/standalone-chrome:latest

# Metadata
LABEL maintainer="Apollo Platform"
LABEL description="Browser automation for AI-driven web testing"
LABEL version="1.0.0"

USER root

# Install additional tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python automation libraries
RUN pip3 install --no-cache-dir \
    selenium \
    playwright \
    beautifulsoup4 \
    requests

# Install Playwright browsers
RUN playwright install chromium

# Create Apollo directories
RUN mkdir -p /opt/apollo/browser-automation
RUN mkdir -p /opt/apollo/evidence
RUN mkdir -p /opt/apollo/screenshots

# Set permissions
RUN chown -R seluser:seluser /opt/apollo

# Switch back to selenium user
USER seluser

# Expose ports
EXPOSE 4444
EXPOSE 5900

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:4444/wd/hub/status || exit 1

# Start Selenium
CMD ["/opt/bin/entry_point.sh"]
