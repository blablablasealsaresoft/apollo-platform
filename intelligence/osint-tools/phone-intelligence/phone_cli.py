#!/usr/bin/env python3
"""
Phone Intelligence CLI
Command-line interface for phone intelligence toolkit
"""

import sys
import json
import argparse
from typing import Optional
from pathlib import Path

try:
    from phone_intel import PhoneIntelligence
    from phone_validator import PhoneValidator
    from phoneinfoga_integration import PhoneInfogaClient
    from truecaller_integration import TrueCallerClient
    from hlr_lookup import HLRLookup
    from sms_intelligence import SMSIntelligence
    from voip_intelligence import VoIPIntelligence
    from phone_correlator import PhoneCorrelator
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all required modules are in the same directory.")
    sys.exit(1)


class PhoneCLI:
    """Command-line interface for phone intelligence"""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize CLI with optional config file"""
        self.config = self._load_config(config_file)
        self.phone_intel = PhoneIntelligence(self.config)
        self.validator = PhoneValidator()

    def _load_config(self, config_file: Optional[str]) -> dict:
        """Load configuration from file"""
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        return {}

    def investigate(self, phone: str, deep: bool = True, output: str = 'text') -> None:
        """
        Investigate a phone number

        Args:
            phone: Phone number to investigate
            deep: Perform deep investigation
            output: Output format (text, json, html)
        """
        print(f"Investigating: {phone}")

        if deep:
            print("Mode: Deep investigation (slower, more comprehensive)")
        else:
            print("Mode: Quick investigation")

        print("-" * 60)

        # Perform investigation
        result = self.phone_intel.investigate(phone, deep=deep)

        # Output results
        if output == 'json':
            print(json.dumps(result, indent=2, default=str))
        elif output == 'html':
            print(self.phone_intel.export_report(result, format='html'))
        else:
            self._print_text_report(result)

    def _print_text_report(self, result: dict) -> None:
        """Print text report to console"""
        # Header
        print(f"\n{'=' * 60}")
        print(f"PHONE INTELLIGENCE REPORT")
        print(f"{'=' * 60}")

        print(f"\nPhone Number: {result.get('phone_number')}")
        print(f"Investigation Time: {result.get('timestamp')}")

        # Summary
        print(f"\n{'=' * 60}")
        print(f"SUMMARY")
        print(f"{'=' * 60}")
        print(result.get('summary', 'No summary available'))

        # Risk Score
        risk = result.get('risk_score', 0)
        print(f"\nRisk Score: {risk}/100", end=" ")

        if risk > 70:
            print("[HIGH RISK] ⚠️")
        elif risk > 40:
            print("[MODERATE RISK] ⚠️")
        else:
            print("[LOW RISK] ✓")

        # Basic Info
        basic = result.get('basic_info', {})
        if basic:
            print(f"\n{'=' * 60}")
            print(f"BASIC INFORMATION")
            print(f"{'=' * 60}")
            print(f"Carrier: {basic.get('carrier', 'Unknown')}")
            print(f"Country: {basic.get('country', 'Unknown')}")
            print(f"Region: {basic.get('region', 'Unknown')}")
            print(f"Type: {basic.get('number_type', 'Unknown')}")

            if basic.get('timezones'):
                print(f"Timezones: {', '.join(basic['timezones'])}")

        # Caller ID
        caller = result.get('caller_id', {})
        if caller and caller.get('name'):
            print(f"\n{'=' * 60}")
            print(f"CALLER ID")
            print(f"{'=' * 60}")
            print(f"Name: {caller.get('name')}")

            if caller.get('spam_score', 0) > 0:
                print(f"Spam Score: {caller['spam_score']}/100")

            if caller.get('is_spam'):
                print("⚠️ WARNING: Reported as SPAM")

        # VoIP Analysis
        voip = result.get('voip_analysis', {})
        if voip and voip.get('is_voip'):
            print(f"\n{'=' * 60}")
            print(f"VOIP ANALYSIS")
            print(f"{'=' * 60}")
            print(f"VoIP Detected: Yes")
            print(f"Provider: {voip.get('provider', 'Unknown')}")
            print(f"Confidence: {voip.get('confidence', 0):.1%}")

        # Breaches
        breaches = result.get('breaches', {})
        if breaches and breaches.get('total_breaches', 0) > 0:
            print(f"\n{'=' * 60}")
            print(f"DATA BREACHES")
            print(f"{'=' * 60}")
            print(f"⚠️ Found in {breaches['total_breaches']} breach(es)")

            found_in = breaches.get('found_in', [])
            for breach in found_in[:5]:
                print(f"  - {breach}")

            if len(found_in) > 5:
                print(f"  ... and {len(found_in) - 5} more")

        # Social Media
        social = result.get('social_media', {})
        if social and social.get('total_found', 0) > 0:
            print(f"\n{'=' * 60}")
            print(f"SOCIAL MEDIA")
            print(f"{'=' * 60}")
            print(f"Found {social['total_found']} account(s):")

            for platform in ['facebook', 'twitter', 'linkedin', 'instagram']:
                if social.get(platform):
                    print(f"  - {platform.title()}: {social[platform]}")

        print(f"\n{'=' * 60}\n")

    def validate(self, phone: str) -> None:
        """Validate a phone number"""
        print(f"Validating: {phone}")
        print("-" * 60)

        result = self.validator.validate(phone)

        if result['is_valid']:
            print("✓ Valid phone number")
            print(f"\nNormalized: {result['normalized']}")
            print(f"Type: {result['metadata'].get('number_type')}")
            print(f"Region: {result['metadata'].get('region')}")
        else:
            print("✗ Invalid phone number")
            print("\nErrors:")
            for error in result['validation_errors']:
                print(f"  - {error}")

        if result['warnings']:
            print("\n⚠️ Warnings:")
            for warning in result['warnings']:
                print(f"  - {warning}")

    def batch(self, file_path: str, deep: bool = False, output: str = 'text') -> None:
        """
        Batch investigate phone numbers from file

        Args:
            file_path: Path to file with phone numbers (one per line)
            deep: Perform deep investigation
            output: Output format
        """
        # Read phone numbers
        with open(file_path, 'r') as f:
            phones = [line.strip() for line in f if line.strip()]

        print(f"Batch investigating {len(phones)} phone numbers...")
        print("-" * 60)

        # Investigate
        results = self.phone_intel.batch_investigate(phones, deep=deep)

        # Output
        if output == 'json':
            print(json.dumps(results, indent=2, default=str))
        else:
            for i, (phone, result) in enumerate(results.items(), 1):
                print(f"\n[{i}/{len(phones)}] {phone}")
                print(f"  Risk: {result.get('risk_score', 0)}/100")
                print(f"  Summary: {result.get('summary', 'N/A')}")

    def export(self, phone: str, format: str, output_file: str) -> None:
        """
        Export phone investigation report

        Args:
            phone: Phone number
            format: Export format (json, html, txt)
            output_file: Output file path
        """
        print(f"Investigating {phone} for export...")

        result = self.phone_intel.investigate(phone, deep=True)

        print(f"Exporting report in {format} format...")

        report = self.phone_intel.export_report(result, format=format)

        with open(output_file, 'w') as f:
            f.write(report)

        print(f"✓ Report saved to: {output_file}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Phone Intelligence OSINT Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Investigate a phone number
  python phone_cli.py investigate +14155552671

  # Quick investigation (no deep analysis)
  python phone_cli.py investigate +14155552671 --quick

  # Validate a phone number
  python phone_cli.py validate +14155552671

  # Batch investigation from file
  python phone_cli.py batch phones.txt

  # Export report to file
  python phone_cli.py export +14155552671 --format html --output report.html

  # Use custom config file
  python phone_cli.py investigate +14155552671 --config config.json
        """
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration JSON file'
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Investigate command
    investigate_parser = subparsers.add_parser('investigate', help='Investigate a phone number')
    investigate_parser.add_argument('phone', help='Phone number to investigate')
    investigate_parser.add_argument('--quick', action='store_true', help='Quick investigation (skip deep analysis)')
    investigate_parser.add_argument('--output', choices=['text', 'json', 'html'], default='text', help='Output format')

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate a phone number')
    validate_parser.add_argument('phone', help='Phone number to validate')

    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Batch investigate phone numbers from file')
    batch_parser.add_argument('file', help='File with phone numbers (one per line)')
    batch_parser.add_argument('--deep', action='store_true', help='Perform deep investigation')
    batch_parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export investigation report')
    export_parser.add_argument('phone', help='Phone number to investigate')
    export_parser.add_argument('--format', choices=['json', 'html', 'txt'], default='txt', help='Export format')
    export_parser.add_argument('--output', required=True, help='Output file path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Initialize CLI
    cli = PhoneCLI(config_file=args.config)

    try:
        # Execute command
        if args.command == 'investigate':
            cli.investigate(args.phone, deep=not args.quick, output=args.output)
        elif args.command == 'validate':
            cli.validate(args.phone)
        elif args.command == 'batch':
            cli.batch(args.file, deep=args.deep, output=args.output)
        elif args.command == 'export':
            cli.export(args.phone, args.format, args.output)

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
