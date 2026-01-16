#!/bin/bash
# Kali Container Entrypoint with Self-Destruct and Evidence Preservation

echo "[Apollo Kali] Container starting..."
echo "[Apollo Kali] Self-destruct timer: ${SELF_DESTRUCT_HOURS} hours"
echo "[Apollo Kali] Evidence preservation: ${PRESERVE_EVIDENCE}"

# Function to preserve evidence before self-destruct
preserve_evidence() {
    echo "[Apollo Kali] ⚠️  Self-destruct timer expired"
    echo "[Apollo Kali] Preserving evidence before cleanup..."

    EVIDENCE_DIR="/opt/apollo/evidence"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    EVIDENCE_FILE="container-${HOSTNAME}-${TIMESTAMP}.tar.gz"

    # Create evidence archive
    tar -czf "${EVIDENCE_DIR}/${EVIDENCE_FILE}" \
        /root/.bash_history \
        /var/log \
        /opt/apollo/logs \
        /tmp/*.log \
        2>/dev/null

    # Generate checksum
    sha256sum "${EVIDENCE_DIR}/${EVIDENCE_FILE}" > "${EVIDENCE_DIR}/${EVIDENCE_FILE}.sha256"

    echo "[Apollo Kali] Evidence archive created: ${EVIDENCE_FILE}"

    # Upload to Apollo evidence vault (if configured)
    if [ -n "$APOLLO_EVIDENCE_VAULT_URL" ]; then
        echo "[Apollo Kali] Uploading evidence to vault..."
        curl -X POST "$APOLLO_EVIDENCE_VAULT_URL/upload" \
             -F "file=@${EVIDENCE_DIR}/${EVIDENCE_FILE}" \
             -F "checksum=@${EVIDENCE_DIR}/${EVIDENCE_FILE}.sha256" \
             -F "authorization=${APOLLO_AUTHORIZATION}" \
             2>/dev/null

        if [ $? -eq 0 ]; then
            echo "[Apollo Kali] Evidence uploaded successfully"
        else
            echo "[Apollo Kali] ⚠️  Evidence upload failed - archive preserved locally"
        fi
    fi

    echo "[Apollo Kali] Evidence preservation complete"
}

# Function to clean up and self-destruct
self_destruct() {
    if [ "$PRESERVE_EVIDENCE" = "true" ]; then
        preserve_evidence
    fi

    echo "[Apollo Kali] 🔥 Initiating self-destruct sequence..."

    # Clear sensitive data
    echo "[Apollo Kali] Clearing bash history..."
    history -c
    > /root/.bash_history

    echo "[Apollo Kali] Clearing system logs..."
    find /var/log -type f -exec truncate -s 0 {} \;

    echo "[Apollo Kali] Clearing temporary files..."
    rm -rf /tmp/*
    rm -rf /var/tmp/*

    echo "[Apollo Kali] Self-destruct complete"
    echo "[Apollo Kali] Container will now shutdown"

    # Shutdown container
    poweroff
}

# Schedule self-destruct
SELF_DESTRUCT_SECONDS=$((SELF_DESTRUCT_HOURS * 3600))
echo "[Apollo Kali] Self-destruct scheduled in ${SELF_DESTRUCT_SECONDS} seconds"

(sleep ${SELF_DESTRUCT_SECONDS} && self_destruct) &

# Trap signals for graceful shutdown
trap 'echo "[Apollo Kali] Received shutdown signal"; preserve_evidence; exit 0' SIGTERM SIGINT

# Start SSH daemon
echo "[Apollo Kali] Starting SSH daemon..."
/usr/sbin/sshd -D &

# Keep container running
echo "[Apollo Kali] Container operational"
echo "[Apollo Kali] Access: ssh root@<container-ip> (password: apollo)"
echo "[Apollo Kali] Self-destruct in: ${SELF_DESTRUCT_HOURS} hours"

# Execute provided command or wait
exec "$@"
