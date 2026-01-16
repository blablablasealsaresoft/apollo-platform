#!/usr/bin/env python3
"""
Dark Web Monitoring System - Example Usage
Demonstrates various monitoring scenarios
"""

import asyncio
import json
from pathlib import Path

from darkweb_monitor import DarkWebMonitor, MonitoringConfig
from onion_crawler import OnionCrawler, CrawlConfig
from marketplace_tracker import MarketplaceTracker
from forum_scraper import ForumScraper
from paste_monitor import PasteMonitor
from telegram_darkweb import TelegramDarkWeb
from tor_proxy import TorProxy
from darkweb_alerts import DarkWebAlerts


async def example_basic_monitoring():
    """Basic dark web monitoring example"""
    print("\n=== Basic Monitoring Example ===\n")

    # Simple configuration
    config = MonitoringConfig(
        keywords=["onecoin", "ruja ignatova", "cryptoqueen"],
        marketplaces=["alphabay", "darkbay"],
        forums=["dread"],
        continuous=False
    )

    # Create and run monitor
    monitor = DarkWebMonitor(config)

    results = await monitor.start_monitoring()

    print(f"[+] Found {len(results)} results")

    # Export results
    json_file = monitor.export_results(format='json')
    html_file = monitor.export_results(format='html')

    print(f"[+] Results exported:")
    print(f"    - JSON: {json_file}")
    print(f"    - HTML: {html_file}")

    # Statistics
    stats = monitor.get_statistics()
    print(f"\n[+] Statistics:")
    print(f"    - Total results: {stats['total_results']}")
    print(f"    - High risk: {stats['high_risk_results']}")
    print(f"    - Total alerts: {stats['total_alerts']}")


async def example_continuous_monitoring():
    """Continuous monitoring with alerts"""
    print("\n=== Continuous Monitoring Example ===\n")

    # Configure alerts
    alerts = DarkWebAlerts(
        webhook_url=None,  # Set to your Slack/Discord webhook
        alert_file="continuous_alerts.jsonl"
    )

    # Advanced configuration
    config = MonitoringConfig(
        keywords=["data breach", "credentials", "database dump"],
        marketplaces=["alphabay", "hydra"],
        forums=["dread", "darknetlive"],
        paste_sites=["pastebin", "ghostbin"],
        continuous=True,
        interval=3600,  # Check every hour
        enable_alerts=True
    )

    monitor = DarkWebMonitor(config)

    print("[*] Starting continuous monitoring...")
    print("[*] Press Ctrl+C to stop")

    try:
        # Run for 2 hours
        await monitor.start_monitoring(duration=7200)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitoring...")
        monitor.stop()


async def example_onion_crawler():
    """Crawl specific onion site"""
    print("\n=== Onion Crawler Example ===\n")

    # Start Tor
    tor_proxy = TorProxy()
    await tor_proxy.start()

    try:
        # Verify Tor connection
        is_tor = await tor_proxy.verify_tor_connection()
        print(f"[*] Connected through Tor: {is_tor}")

        # Configure crawler
        config = CrawlConfig(
            max_depth=2,
            max_pages=50,
            delay=3.0,
            extract_emails=True,
            extract_crypto=True
        )

        crawler = OnionCrawler(tor_proxy, config)

        # Example onion URL (replace with actual URL)
        start_url = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"

        print(f"[*] Crawling {start_url}")
        pages = await crawler.crawl(start_url)

        print(f"[+] Crawled {len(pages)} pages")

        # Generate sitemap
        sitemap = crawler.generate_sitemap("onion_sitemap.md")
        print(f"[+] Sitemap generated")

        # Export results
        crawler.export_results("crawl_results.json")
        print(f"[+] Results exported")

        # Statistics
        stats = crawler.get_statistics()
        print(f"\n[+] Crawler Statistics:")
        print(f"    - Pages crawled: {stats['pages_crawled']}")
        print(f"    - Emails found: {stats['emails_found']}")
        print(f"    - Crypto addresses: {stats['crypto_addresses_found']}")

    finally:
        await tor_proxy.stop()


async def example_marketplace_tracking():
    """Track dark web marketplaces"""
    print("\n=== Marketplace Tracking Example ===\n")

    tor_proxy = TorProxy()
    await tor_proxy.start()

    try:
        tracker = MarketplaceTracker(tor_proxy)

        # Get marketplace list
        marketplaces = tracker.get_marketplace_list()
        print(f"[*] Known marketplaces: {len(marketplaces)}")

        for market in marketplaces[:5]:
            print(f"    - {market['name']} ({market['status']})")

        # Track specific marketplace
        print(f"\n[*] Tracking marketplace...")
        results = await tracker.track_marketplace(
            "alphabay",
            keywords=["stolen data", "credentials"],
            categories=["fraud"]
        )

        print(f"[+] Found {len(results)} results")

        # Generate report
        report = tracker.generate_market_report()
        print(f"\n{report}")

    finally:
        await tor_proxy.stop()


async def example_forum_scraping():
    """Scrape dark web forums"""
    print("\n=== Forum Scraping Example ===\n")

    tor_proxy = TorProxy()
    await tor_proxy.start()

    try:
        scraper = ForumScraper(tor_proxy)

        # Get forum list
        forums = scraper.get_forum_list()
        print(f"[*] Known forums: {len(forums)}")

        for forum in forums[:5]:
            print(f"    - {forum['name']} ({forum['status']})")

        # Scrape forum
        print(f"\n[*] Scraping forum...")
        results = await scraper.scrape_forum(
            "dread",
            keywords=["exploit", "vulnerability", "zero-day"],
            boards=["security"],
            max_pages=5
        )

        print(f"[+] Found {len(results)} results")

        # Generate report
        report = scraper.generate_forum_report()
        print(f"\n{report}")

    finally:
        await tor_proxy.stop()


async def example_paste_monitoring():
    """Monitor paste sites for leaks"""
    print("\n=== Paste Site Monitoring Example ===\n")

    monitor = PasteMonitor()

    # Monitor for credentials
    print("[*] Monitoring paste sites...")
    results = await monitor.monitor(
        keywords=[
            "database dump",
            "credentials",
            "password",
            "@company.com"
        ],
        sites=["pastebin", "ghostbin"],
        continuous=False
    )

    print(f"[+] Found {len(results)} results")

    # Generate report
    report = monitor.generate_report()
    print(f"\n{report}")

    # Export results
    monitor.export_results("paste_results.json")
    print(f"[+] Results exported")


async def example_telegram_monitoring():
    """Monitor Telegram channels"""
    print("\n=== Telegram Monitoring Example ===\n")

    # Note: Requires API credentials
    monitor = TelegramDarkWeb(
        api_id=None,  # Set your API ID
        api_hash=None  # Set your API hash
    )

    # Monitor channels
    print("[*] Monitoring Telegram channels...")
    results = await monitor.monitor_channels(
        channels=["@darknet_news", "@marketplace_alerts"],
        keywords=["breach", "leak", "hack"],
        continuous=False
    )

    print(f"[+] Found {len(results)} results")

    # Generate report
    report = monitor.generate_report()
    print(f"\n{report}")


async def example_comprehensive_monitoring():
    """Comprehensive monitoring across all sources"""
    print("\n=== Comprehensive Monitoring Example ===\n")

    # Load configuration
    config_file = Path("config.json")
    if config_file.exists():
        with open(config_file) as f:
            config_data = json.load(f)

        config = MonitoringConfig(
            keywords=config_data['monitoring']['keywords'],
            marketplaces=config_data['monitoring']['marketplaces'],
            forums=config_data['monitoring']['forums'],
            paste_sites=config_data['monitoring']['paste_sites'],
            telegram_channels=config_data['monitoring']['telegram_channels'],
            tor_search_engines=config_data['monitoring']['tor_search_engines'],
            continuous=config_data['monitoring_config']['continuous'],
            interval=config_data['monitoring_config']['interval'],
            output_dir=config_data['monitoring_config']['output_dir'],
            enable_alerts=config_data['monitoring_config']['enable_alerts'],
            alert_webhook=config_data['alerts']['webhook_url']
        )
    else:
        # Default configuration
        config = MonitoringConfig(
            keywords=["onecoin", "ruja ignatova"],
            marketplaces=["alphabay"],
            forums=["dread"],
            paste_sites=["pastebin"],
            continuous=False
        )

    # Create monitor
    monitor = DarkWebMonitor(config)

    print("[*] Starting comprehensive monitoring...")
    print(f"[*] Keywords: {config.keywords}")
    print(f"[*] Sources: Marketplaces, Forums, Paste Sites, Tor Search")

    # Start monitoring
    results = await monitor.start_monitoring()

    print(f"\n[+] Monitoring complete!")
    print(f"[+] Total results: {len(results)}")

    # Export in multiple formats
    json_file = monitor.export_results(format='json')
    html_file = monitor.export_results(format='html')
    csv_file = monitor.export_results(format='csv')

    print(f"\n[+] Results exported:")
    print(f"    - JSON: {json_file}")
    print(f"    - HTML: {html_file}")
    print(f"    - CSV: {csv_file}")

    # Statistics
    stats = monitor.get_statistics()
    print(f"\n[+] Final Statistics:")
    print(f"    - Total results: {stats['total_results']}")
    print(f"    - By source type: {stats['by_source_type']}")
    print(f"    - High risk results: {stats['high_risk_results']}")
    print(f"    - Total alerts: {stats['total_alerts']}")


async def example_tor_proxy():
    """Tor proxy management example"""
    print("\n=== Tor Proxy Example ===\n")

    proxy = TorProxy()

    try:
        # Start Tor
        print("[*] Starting Tor proxy...")
        await proxy.start()

        # Verify connection
        is_tor = await proxy.verify_tor_connection()
        print(f"[+] Connected through Tor: {is_tor}")

        # Get current IP
        ip = await proxy.get_current_ip()
        print(f"[+] Current exit IP: {ip}")

        # Rotate circuit
        print("[*] Rotating circuit...")
        await proxy.rotate_circuit()
        await asyncio.sleep(5)

        # Get new IP
        new_ip = await proxy.get_current_ip()
        print(f"[+] New exit IP: {new_ip}")

        # Get status
        status = proxy.get_status()
        print(f"\n[+] Tor Status:")
        print(f"    - Running: {status['running']}")
        print(f"    - SOCKS port: {status['socks_port']}")
        print(f"    - Proxy URL: {status['proxy_url']}")

    finally:
        await proxy.stop()
        proxy.cleanup()


def main_menu():
    """Interactive menu"""
    print("\n" + "="*60)
    print("Dark Web Monitoring System - Example Usage")
    print("="*60)
    print("\n1. Basic Monitoring")
    print("2. Continuous Monitoring (with alerts)")
    print("3. Onion Site Crawler")
    print("4. Marketplace Tracking")
    print("5. Forum Scraping")
    print("6. Paste Site Monitoring")
    print("7. Telegram Monitoring")
    print("8. Comprehensive Monitoring")
    print("9. Tor Proxy Management")
    print("0. Exit")

    choice = input("\nSelect example (0-9): ")

    examples = {
        '1': example_basic_monitoring,
        '2': example_continuous_monitoring,
        '3': example_onion_crawler,
        '4': example_marketplace_tracking,
        '5': example_forum_scraping,
        '6': example_paste_monitoring,
        '7': example_telegram_monitoring,
        '8': example_comprehensive_monitoring,
        '9': example_tor_proxy
    }

    if choice in examples:
        asyncio.run(examples[choice]())
    elif choice == '0':
        print("\nExiting...")
    else:
        print("\nInvalid choice!")


if __name__ == "__main__":
    # Run interactive menu
    try:
        while True:
            main_menu()
            input("\nPress Enter to continue...")
    except KeyboardInterrupt:
        print("\n\nExiting...")
