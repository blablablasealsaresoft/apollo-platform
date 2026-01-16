"""
PhoneInfoga Integration
International phone lookup and carrier identification
"""

import requests
import subprocess
import json
import logging
from typing import Dict, List, Optional, Any
import tempfile
import os


class PhoneInfogaClient:
    """
    PhoneInfoga integration for phone number intelligence
    Supports both CLI and API modes
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PhoneInfoga client

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # API mode or CLI mode
        self.api_url = self.config.get('api_url', 'http://localhost:5000')
        self.use_cli = self.config.get('use_cli', False)
        self.cli_path = self.config.get('cli_path', 'phoneinfoga')

        # Google Dorking options
        self.enable_google_dork = self.config.get('google_dork', False)

        self.logger.info("PhoneInfoga client initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('PhoneInfoga')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def lookup(self, phone: str) -> Dict[str, Any]:
        """
        Lookup phone number information

        Args:
            phone: Phone number in E.164 format

        Returns:
            Dictionary with phone information
        """
        if self.use_cli:
            return self._lookup_cli(phone)
        else:
            return self._lookup_api(phone)

    def _lookup_api(self, phone: str) -> Dict[str, Any]:
        """Lookup using PhoneInfoga API"""
        try:
            self.logger.info(f"Looking up {phone} via API")

            # Scan number
            scan_url = f"{self.api_url}/api/numbers/{phone}/scan"
            response = requests.get(scan_url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_api_response(data)
            else:
                self.logger.error(f"API error: {response.status_code}")
                return {'error': f"API returned status {response.status_code}"}

        except Exception as e:
            self.logger.error(f"Error in API lookup: {e}")
            return {'error': str(e)}

    def _lookup_cli(self, phone: str) -> Dict[str, Any]:
        """Lookup using PhoneInfoga CLI"""
        try:
            self.logger.info(f"Looking up {phone} via CLI")

            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
                output_file = f.name

            try:
                # Run phoneinfoga CLI
                cmd = [
                    self.cli_path,
                    'scan',
                    '-n', phone,
                    '-o', output_file
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    # Read output file
                    if os.path.exists(output_file):
                        with open(output_file, 'r') as f:
                            data = json.load(f)
                        return self._parse_cli_response(data)
                    else:
                        return {'error': 'No output file generated'}
                else:
                    self.logger.error(f"CLI error: {result.stderr}")
                    return {'error': result.stderr}

            finally:
                # Clean up temp file
                if os.path.exists(output_file):
                    os.unlink(output_file)

        except subprocess.TimeoutExpired:
            self.logger.error("CLI lookup timed out")
            return {'error': 'Lookup timed out'}
        except Exception as e:
            self.logger.error(f"Error in CLI lookup: {e}")
            return {'error': str(e)}

    def _parse_api_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse API response into standardized format"""
        result = {
            'carrier': {},
            'location': {},
            'line_type': None,
            'international': {},
            'raw': data
        }

        # Extract carrier information
        if 'carrier' in data:
            result['carrier'] = {
                'name': data['carrier'].get('name'),
                'mobile_country_code': data['carrier'].get('mcc'),
                'mobile_network_code': data['carrier'].get('mnc'),
                'type': data['carrier'].get('type')
            }

        # Extract location
        if 'country' in data:
            result['location'] = {
                'country': data.get('country'),
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'timezone': data.get('timezone')
            }

        # Line type
        result['line_type'] = data.get('line_type', 'UNKNOWN')

        # International format
        if 'international_format' in data:
            result['international'] = {
                'format': data.get('international_format'),
                'e164': data.get('e164_format'),
                'national': data.get('national_format')
            }

        return result

    def _parse_cli_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CLI response into standardized format"""
        # CLI output structure may vary, adapt as needed
        return self._parse_api_response(data)

    def bulk_lookup(self, phones: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Lookup multiple phone numbers

        Args:
            phones: List of phone numbers

        Returns:
            Dictionary mapping phone numbers to results
        """
        results = {}

        for phone in phones:
            results[phone] = self.lookup(phone)

        return results

    def google_dork_search(self, phone: str) -> List[Dict[str, str]]:
        """
        Perform Google dorking for phone number

        Args:
            phone: Phone number to search

        Returns:
            List of search results
        """
        if not self.enable_google_dork:
            self.logger.warning("Google dorking is disabled")
            return []

        try:
            # Common Google dork patterns for phone numbers
            dorks = [
                f'"{phone}"',
                f'"{phone}" site:facebook.com',
                f'"{phone}" site:linkedin.com',
                f'"{phone}" site:twitter.com',
                f'"{phone}" site:instagram.com',
                f'"{phone}" intext:"phone" OR intext:"contact"',
                f'"{phone}" filetype:pdf',
                f'"{phone}" filetype:doc',
                f'"{phone}" filetype:xls'
            ]

            results = []

            # Note: Actual Google search would require API key or scraping
            # This is a placeholder for the structure
            for dork in dorks:
                results.append({
                    'query': dork,
                    'description': f'Search for {phone} using Google dork',
                    'url': f'https://www.google.com/search?q={dork.replace(" ", "+")}'
                })

            self.logger.info(f"Generated {len(results)} Google dork queries")
            return results

        except Exception as e:
            self.logger.error(f"Error in Google dorking: {e}")
            return []

    def get_carrier_info(self, phone: str) -> Dict[str, Any]:
        """
        Get detailed carrier information

        Args:
            phone: Phone number

        Returns:
            Carrier information dictionary
        """
        lookup_result = self.lookup(phone)
        return lookup_result.get('carrier', {})

    def get_location_info(self, phone: str) -> Dict[str, Any]:
        """
        Get location information

        Args:
            phone: Phone number

        Returns:
            Location information dictionary
        """
        lookup_result = self.lookup(phone)
        return lookup_result.get('location', {})

    def is_mobile(self, phone: str) -> bool:
        """
        Check if number is mobile

        Args:
            phone: Phone number

        Returns:
            True if mobile, False otherwise
        """
        lookup_result = self.lookup(phone)
        line_type = lookup_result.get('line_type', '').upper()
        return 'MOBILE' in line_type

    def is_landline(self, phone: str) -> bool:
        """
        Check if number is landline

        Args:
            phone: Phone number

        Returns:
            True if landline, False otherwise
        """
        lookup_result = self.lookup(phone)
        line_type = lookup_result.get('line_type', '').upper()
        return 'FIXED' in line_type or 'LANDLINE' in line_type


def main():
    """Example usage"""
    # Initialize client
    client = PhoneInfogaClient({
        'api_url': 'http://localhost:5000',
        'use_cli': False,
        'google_dork': True
    })

    # Lookup phone number
    phone = "+14155552671"
    result = client.lookup(phone)

    print(f"Lookup result for {phone}:")
    print(json.dumps(result, indent=2))

    # Check if mobile
    if client.is_mobile(phone):
        print(f"{phone} is a mobile number")

    # Get carrier
    carrier = client.get_carrier_info(phone)
    print(f"Carrier: {carrier.get('name')}")

    # Google dorking
    dorks = client.google_dork_search(phone)
    print(f"\nGenerated {len(dorks)} Google dork queries")


if __name__ == "__main__":
    main()
