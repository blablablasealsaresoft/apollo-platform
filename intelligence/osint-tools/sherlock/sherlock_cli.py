"""
Sherlock CLI - Command Line Interface for OSINT Username Search

Production-ready CLI tool for username reconnaissance across social media platforms.

Author: Apollo Intelligence Platform
License: MIT
"""

import argparse
import sys
import logging
from pathlib import Path
import json
from typing import List, Optional
from datetime import datetime
import colorama
from colorama import Fore, Style, Back
from tabulate import tabulate

# Initialize colorama for Windows support
colorama.init(autoreset=True)

from sherlock_integration import SherlockOSINT, BatchSearchResult
from sherlock_async import SherlockAsync


class SherlockCLI:
    """
    Command-line interface for Sherlock OSINT
    """

    def __init__(self):
        """Initialize CLI"""
        self.logger = self._setup_logging()
        self.sherlock = None

    def _setup_logging(self, verbose: bool = False) -> logging.Logger:
        """Setup logging configuration"""
        level = logging.DEBUG if verbose else logging.INFO

        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        return logging.getLogger(__name__)

    def print_banner(self):
        """Print ASCII banner"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   {Fore.YELLOW}███████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗  ██████╗██╗  ██╗{Fore.CYAN}   ║
║   {Fore.YELLOW}██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝{Fore.CYAN}   ║
║   {Fore.YELLOW}███████╗███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╔╝{Fore.CYAN}    ║
║   {Fore.YELLOW}╚════██║██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗{Fore.CYAN}    ║
║   {Fore.YELLOW}███████║██║  ██║███████╗██║  ██║███████╗╚██████╔╝╚██████╗██║  ██╗{Fore.CYAN}   ║
║   {Fore.YELLOW}╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝{Fore.CYAN}   ║
║                                                                       ║
║              {Fore.GREEN}OSINT Username Search Across 400+ Platforms{Fore.CYAN}              ║
║                    {Fore.MAGENTA}Apollo Intelligence Platform{Fore.CYAN}                     ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def search_username(self,
                       username: str,
                       use_async: bool = True,
                       platforms: Optional[List[str]] = None,
                       categories: Optional[List[str]] = None,
                       output_format: str = 'table',
                       output_file: Optional[str] = None,
                       min_confidence: float = 0.0):
        """
        Search for username across platforms

        Args:
            username: Username to search
            use_async: Use async implementation
            platforms: Specific platforms to search
            categories: Platform categories to filter
            output_format: Output format (table, json, csv, markdown)
            output_file: Output file path
            min_confidence: Minimum confidence threshold
        """
        print(f"\n{Fore.CYAN}[*] Starting search for username: {Fore.YELLOW}{username}{Style.RESET_ALL}")

        if use_async:
            print(f"{Fore.GREEN}[+] Using async implementation (high-performance mode){Style.RESET_ALL}")
            self.sherlock = SherlockAsync(max_concurrent=50)
        else:
            print(f"{Fore.GREEN}[+] Using sync implementation{Style.RESET_ALL}")
            self.sherlock = SherlockOSINT(max_workers=20)

        # Execute search
        try:
            if use_async:
                import asyncio
                results = asyncio.run(
                    self.sherlock.search_username_async(
                        username,
                        platforms=platforms,
                        categories=categories,
                        show_progress=True
                    )
                )
            else:
                results = self.sherlock.search_username(
                    username,
                    platforms=platforms,
                    categories=categories,
                    min_confidence=min_confidence
                )

            # Display results
            self.display_results(results, output_format)

            # Export if requested
            if output_file:
                self.export_results(results, output_file, output_format)

            # Display summary
            self.display_summary(results)

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Search interrupted by user{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Search failed: {e}{Style.RESET_ALL}")
            self.logger.error(f"Search error: {e}", exc_info=True)
            sys.exit(1)

    def batch_search(self,
                    usernames: List[str],
                    use_async: bool = True,
                    output_dir: Optional[str] = None):
        """
        Search multiple usernames

        Args:
            usernames: List of usernames to search
            use_async: Use async implementation
            output_dir: Output directory for results
        """
        print(f"\n{Fore.CYAN}[*] Starting batch search for {len(usernames)} usernames{Style.RESET_ALL}")

        if use_async:
            self.sherlock = SherlockAsync(max_concurrent=50)
        else:
            self.sherlock = SherlockOSINT(max_workers=20)

        all_results = []

        for i, username in enumerate(usernames, 1):
            print(f"\n{Fore.CYAN}[{i}/{len(usernames)}] Searching: {Fore.YELLOW}{username}{Style.RESET_ALL}")

            try:
                if use_async:
                    import asyncio
                    results = asyncio.run(
                        self.sherlock.search_username_async(username, show_progress=True)
                    )
                else:
                    results = self.sherlock.search_username(username)

                all_results.append(results)

                # Brief summary
                print(f"{Fore.GREEN}[+] Found on {results.found_platforms}/{results.total_platforms} platforms{Style.RESET_ALL}")

                # Export individual results
                if output_dir:
                    output_path = Path(output_dir) / f"{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    self.export_results(results, str(output_path), 'json')

            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to search {username}: {e}{Style.RESET_ALL}")
                continue

        # Display batch summary
        self.display_batch_summary(all_results)

    def display_results(self, results: BatchSearchResult, format: str = 'table'):
        """Display search results"""
        found_results = [r for r in results.results if r.exists]

        if not found_results:
            print(f"\n{Fore.YELLOW}[!] No accounts found for username: {results.username}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}[+] Found {len(found_results)} accounts:{Style.RESET_ALL}\n")

        if format == 'table':
            self._display_table(found_results)
        elif format == 'simple':
            self._display_simple(found_results)
        elif format == 'detailed':
            self._display_detailed(found_results)

    def _display_table(self, results: List):
        """Display results in table format"""
        table_data = []

        for i, result in enumerate(results, 1):
            confidence_color = self._get_confidence_color(result.confidence)
            table_data.append([
                i,
                result.platform,
                f"{confidence_color}{result.confidence:.0%}{Style.RESET_ALL}",
                result.additional_data.get('category', 'unknown') if result.additional_data else 'unknown',
                result.url
            ])

        headers = ['#', 'Platform', 'Confidence', 'Category', 'URL']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))

    def _display_simple(self, results: List):
        """Display results in simple format"""
        for result in results:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {result.platform:20s} {result.url}")

    def _display_detailed(self, results: List):
        """Display results in detailed format"""
        for i, result in enumerate(results, 1):
            confidence_color = self._get_confidence_color(result.confidence)
            category = result.additional_data.get('category', 'unknown') if result.additional_data else 'unknown'

            print(f"{Fore.CYAN}[{i}] {result.platform}{Style.RESET_ALL}")
            print(f"    URL:        {result.url}")
            print(f"    Confidence: {confidence_color}{result.confidence:.0%}{Style.RESET_ALL}")
            print(f"    Category:   {category}")
            print(f"    Status:     HTTP {result.http_status}")
            print(f"    Time:       {result.response_time:.2f}s")
            print()

    def _get_confidence_color(self, confidence: float) -> str:
        """Get color based on confidence level"""
        if confidence >= 0.9:
            return Fore.GREEN
        elif confidence >= 0.7:
            return Fore.YELLOW
        else:
            return Fore.RED

    def display_summary(self, results: BatchSearchResult):
        """Display search summary"""
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"SEARCH SUMMARY")
        print(f"{'=' * 70}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}Username:{Style.RESET_ALL}         {results.username}")
        print(f"{Fore.CYAN}Platforms Checked:{Style.RESET_ALL} {results.total_platforms}")
        print(f"{Fore.CYAN}Platforms Found:{Style.RESET_ALL}   {Fore.GREEN}{results.found_platforms}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Search Duration:{Style.RESET_ALL}   {results.search_duration:.2f}s")
        print(f"{Fore.CYAN}Speed:{Style.RESET_ALL}            {results.total_platforms / results.search_duration:.2f} platforms/sec")

        # Category breakdown
        category_counts = {}
        for result in results.results:
            if result.exists and result.additional_data:
                category = result.additional_data.get('category', 'unknown')
                category_counts[category] = category_counts.get(category, 0) + 1

        if category_counts:
            print(f"\n{Fore.CYAN}Category Breakdown:{Style.RESET_ALL}")
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {category:20s} {count:3d}")

        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")

    def display_batch_summary(self, all_results: List[BatchSearchResult]):
        """Display batch search summary"""
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"BATCH SEARCH SUMMARY")
        print(f"{'=' * 70}{Style.RESET_ALL}")

        total_usernames = len(all_results)
        total_platforms_checked = sum(r.total_platforms for r in all_results)
        total_platforms_found = sum(r.found_platforms for r in all_results)
        total_duration = sum(r.search_duration for r in all_results)

        print(f"{Fore.CYAN}Usernames Searched:{Style.RESET_ALL}    {total_usernames}")
        print(f"{Fore.CYAN}Total Platforms Checked:{Style.RESET_ALL} {total_platforms_checked}")
        print(f"{Fore.CYAN}Total Platforms Found:{Style.RESET_ALL}   {Fore.GREEN}{total_platforms_found}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total Duration:{Style.RESET_ALL}         {total_duration:.2f}s")
        print(f"{Fore.CYAN}Average per Username:{Style.RESET_ALL}   {total_duration / total_usernames:.2f}s")

        print(f"\n{Fore.CYAN}Results by Username:{Style.RESET_ALL}")
        for result in all_results:
            success_rate = result.found_platforms / result.total_platforms
            color = Fore.GREEN if success_rate > 0.1 else Fore.YELLOW if success_rate > 0 else Fore.RED
            print(f"  {result.username:20s} {color}{result.found_platforms:3d}/{result.total_platforms:3d}{Style.RESET_ALL} ({success_rate:.1%})")

        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")

    def export_results(self, results: BatchSearchResult, output_file: str, format: str):
        """Export results to file"""
        try:
            # Ensure parent directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if format == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(results.to_dict(), f, indent=2, ensure_ascii=False)

            elif format == 'csv':
                import csv
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Platform', 'URL', 'Exists', 'Confidence', 'Category', 'HTTP Status', 'Response Time'])

                    for result in results.results:
                        category = result.additional_data.get('category', '') if result.additional_data else ''
                        writer.writerow([
                            result.platform,
                            result.url,
                            result.exists,
                            result.confidence,
                            category,
                            result.http_status,
                            f"{result.response_time:.2f}"
                        ])

            elif format == 'markdown':
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Sherlock OSINT Report: {results.username}\n\n")
                    f.write(f"**Date:** {results.timestamp}\n\n")
                    f.write(f"**Platforms Checked:** {results.total_platforms}\n\n")
                    f.write(f"**Platforms Found:** {results.found_platforms}\n\n")
                    f.write(f"**Duration:** {results.search_duration:.2f}s\n\n")

                    found_results = [r for r in results.results if r.exists]

                    if found_results:
                        f.write("## Found Accounts\n\n")
                        f.write("| Platform | URL | Confidence | Category |\n")
                        f.write("|----------|-----|------------|----------|\n")

                        for result in found_results:
                            category = result.additional_data.get('category', 'unknown') if result.additional_data else 'unknown'
                            f.write(f"| {result.platform} | {result.url} | {result.confidence:.0%} | {category} |\n")

            print(f"{Fore.GREEN}[+] Results exported to: {output_path}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to export results: {e}{Style.RESET_ALL}")
            self.logger.error(f"Export error: {e}", exc_info=True)

    def interactive_mode(self):
        """Interactive CLI mode"""
        self.print_banner()

        print(f"{Fore.CYAN}Interactive Mode - Type 'help' for commands, 'exit' to quit{Style.RESET_ALL}\n")

        while True:
            try:
                user_input = input(f"{Fore.YELLOW}sherlock>{Style.RESET_ALL} ").strip()

                if not user_input:
                    continue

                if user_input.lower() in ['exit', 'quit', 'q']:
                    print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}")
                    break

                elif user_input.lower() in ['help', '?']:
                    self.print_help()

                elif user_input.lower().startswith('search '):
                    username = user_input[7:].strip()
                    if username:
                        self.search_username(username, use_async=True, output_format='table')
                    else:
                        print(f"{Fore.RED}[ERROR] Usage: search <username>{Style.RESET_ALL}")

                else:
                    # Treat input as username search
                    self.search_username(user_input, use_async=True, output_format='table')

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Use 'exit' to quit{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

    def print_help(self):
        """Print help information"""
        help_text = f"""
{Fore.CYAN}{'=' * 70}
SHERLOCK CLI - HELP
{'=' * 70}{Style.RESET_ALL}

{Fore.YELLOW}Commands:{Style.RESET_ALL}
  search <username>    Search for a username
  <username>           Same as 'search <username>'
  help, ?              Show this help
  exit, quit, q        Exit interactive mode

{Fore.YELLOW}Examples:{Style.RESET_ALL}
  sherlock> search john_doe
  sherlock> ruja_ignatova
  sherlock> exit

{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}
"""
        print(help_text)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Sherlock OSINT - Username Search Across 400+ Platforms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sherlock_cli.py username                          # Search username
  sherlock_cli.py -u username1 username2 username3  # Search multiple
  sherlock_cli.py -i                                # Interactive mode
  sherlock_cli.py username --async                  # Use async (faster)
  sherlock_cli.py username -o results.json          # Export to JSON
  sherlock_cli.py username -c social gaming         # Filter categories
        """
    )

    # Username arguments
    parser.add_argument(
        'usernames',
        nargs='*',
        help='Username(s) to search'
    )

    parser.add_argument(
        '-u', '--usernames-file',
        type=str,
        help='File containing usernames (one per line)'
    )

    # Search options
    parser.add_argument(
        '--async',
        dest='use_async',
        action='store_true',
        default=True,
        help='Use async implementation (default, faster)'
    )

    parser.add_argument(
        '--sync',
        dest='use_async',
        action='store_false',
        help='Use sync implementation'
    )

    parser.add_argument(
        '-p', '--platforms',
        nargs='+',
        help='Specific platforms to check'
    )

    parser.add_argument(
        '-c', '--categories',
        nargs='+',
        help='Platform categories to check (e.g., social, gaming, development)'
    )

    parser.add_argument(
        '--min-confidence',
        type=float,
        default=0.0,
        help='Minimum confidence threshold (0.0-1.0)'
    )

    # Output options
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['table', 'simple', 'detailed', 'json', 'csv', 'markdown'],
        default='table',
        help='Output format (default: table)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        help='Output directory for batch searches'
    )

    # Interactive mode
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Start interactive mode'
    )

    # Logging
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose logging'
    )

    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Hide ASCII banner'
    )

    args = parser.parse_args()

    # Initialize CLI
    cli = SherlockCLI()

    if args.verbose:
        cli._setup_logging(verbose=True)

    # Print banner
    if not args.no_banner and not args.interactive:
        cli.print_banner()

    # Interactive mode
    if args.interactive:
        cli.interactive_mode()
        return

    # Get usernames
    usernames = args.usernames or []

    if args.usernames_file:
        try:
            with open(args.usernames_file, 'r') as f:
                file_usernames = [line.strip() for line in f if line.strip()]
                usernames.extend(file_usernames)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to read usernames file: {e}{Style.RESET_ALL}")
            sys.exit(1)

    if not usernames:
        parser.print_help()
        sys.exit(0)

    # Single or batch search
    if len(usernames) == 1:
        cli.search_username(
            usernames[0],
            use_async=args.use_async,
            platforms=args.platforms,
            categories=args.categories,
            output_format=args.format,
            output_file=args.output,
            min_confidence=args.min_confidence
        )
    else:
        cli.batch_search(
            usernames,
            use_async=args.use_async,
            output_dir=args.output_dir
        )


if __name__ == "__main__":
    main()
