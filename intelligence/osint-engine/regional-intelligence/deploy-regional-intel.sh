#!/bin/bash
# Deploy Regional Intelligence for Ignatova Hunt
# Apollo Platform - Deployment Script

echo "═══════════════════════════════════════════════════════════"
echo "  Apollo Regional Intelligence Deployment"
echo "  Case: HVT-CRYPTO-2026-001 (Ruja Ignatova)"
echo "═══════════════════════════════════════════════════════════"

# Check if running in Apollo environment
if [ -z "$APOLLO_HOME" ]; then
    export APOLLO_HOME="$(cd ../../.. && pwd)"
fi

cd "$(dirname "$0")"

# Install dependencies
echo "[1/5] Installing dependencies..."
pip install -r requirements.txt

# Configure API keys
echo "[2/5] Checking API keys..."
if [ -z "$VK_ACCESS_TOKEN" ]; then
    echo "Warning: VK_ACCESS_TOKEN not set"
fi
if [ -z "$XING_API_KEY" ]; then
    echo "Warning: XING_API_KEY not set (web scraping will be used)"
fi

# Deploy Russian OSINT
echo "[3/5] Deploying Russian OSINT..."
python russian-osint/vk-advanced-search.py &
python russian-osint/odnoklassniki-scraper.py &
python russian-osint/russian-forum-crawler.py &

# Deploy Bulgarian monitoring
echo "[4/5] Deploying Bulgarian intelligence..."
python bulgarian-balkan/bulgarian-news-scraper.py &

# Deploy German intelligence
echo "[5/5] Deploying German intelligence..."
python german-intelligence/xing-integration.py &

# Deploy UAE intelligence
echo "[5/5] Deploying UAE intelligence..."
python uae-intelligence/dubai-expat-forums.py &

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Regional Intelligence Deployment Complete"
echo "═══════════════════════════════════════════════════════════"
echo "Monitoring:"
echo "  ✓ VK.com (Russian social)"
echo "  ✓ Odnoklassniki (Russian social)"
echo "  ✓ Russian forums"
echo "  ✓ Bulgarian news sources"
echo "  ✓ XING (German professional)"
echo "  ✓ Dubai expat communities"
echo ""
echo "Status: Continuous monitoring active"
echo "AI Integration: Feeding to Apollo intelligence fusion"
echo "Case: HVT-CRYPTO-2026-001"
echo "Target: Ruja Ignatova"
echo ""
echo "Monitor with: apollo-osint regional-status"
echo "═══════════════════════════════════════════════════════════"
