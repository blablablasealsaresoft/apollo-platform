FROM kalilinux/kali-rolling:latest

# Metadata
LABEL maintainer="Apollo Platform"
LABEL description="Kali Linux container for AI-driven penetration testing"
LABEL version="1.0.0"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV SELF_DESTRUCT_HOURS=24
ENV PRESERVE_EVIDENCE=true
ENV APOLLO_MODE=true

# Update and install base tools
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    # Network scanning
    nmap masscan rustscan \
    # Exploitation frameworks
    metasploit-framework \
    # Web testing
    sqlmap wpscan nikto dirb gobuster \
    # Password cracking
    john hashcat hydra \
    # Post-exploitation
    responder impacket-scripts \
    # Active Directory
    bloodhound crackmapexec \
    # Wireless
    aircrack-ng reaver \
    # Utilities
    python3 python3-pip python3-venv \
    nodejs npm \
    git curl wget \
    vim nano \
    openssh-server \
    # System utilities
    net-tools iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python tools
RUN pip3 install --no-cache-dir \
    requests \
    beautifulsoup4 \
    pycryptodome \
    scapy \
    impacket

# Create Apollo tools directory
RUN mkdir -p /opt/apollo/tools
RUN mkdir -p /opt/apollo/evidence
RUN mkdir -p /opt/apollo/logs

# Configure SSH
RUN mkdir -p /var/run/sshd
RUN echo 'root:apollo' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# SSH login fix
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy Apollo-specific tools (placeholder)
# COPY apollo-tools/ /opt/apollo/tools/

# Expose SSH port (randomized at runtime)
EXPOSE 22

# Set working directory
WORKDIR /root

# Entrypoint with self-destruct mechanism
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["/usr/sbin/sshd", "-D"]
