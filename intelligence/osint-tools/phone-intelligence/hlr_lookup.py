"""
HLR Lookup - Home Location Register Query
Network status, roaming status, and IMSI identification
"""

import requests
import json
import logging
from typing import Dict, Optional, Any, List
import time


class HLRLookup:
    """
    Home Location Register (HLR) lookup service
    Query mobile network information
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize HLR lookup service

        Args:
            config: Configuration dictionary with API credentials
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # API configuration - supports multiple providers
        self.provider = self.config.get('provider', 'hlr-lookups')
        self.api_key = self.config.get('api_key')
        self.api_url = self.config.get('api_url', self._get_default_api_url())

        # Rate limiting
        self.rate_limit = self.config.get('rate_limit', 30)
        self.last_request_time = 0

        # Session
        self.session = requests.Session()
        self._setup_session()

        self.logger.info(f"HLR lookup initialized with provider: {self.provider}")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('HLRLookup')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _get_default_api_url(self) -> str:
        """Get default API URL based on provider"""
        urls = {
            'hlr-lookups': 'https://www.hlr-lookups.com/api',
            'nexmo': 'https://api.nexmo.com/ni/advanced/json',
            'twilio': 'https://lookups.twilio.com/v1/PhoneNumbers',
            'numverify': 'https://apilayer.net/api/validate'
        }
        return urls.get(self.provider, urls['hlr-lookups'])

    def _setup_session(self):
        """Setup session with headers"""
        self.session.headers.update({
            'User-Agent': 'HLRLookup/1.0',
            'Accept': 'application/json'
        })

        if self.api_key and self.provider != 'hlr-lookups':
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}'
            })

    def _rate_limit_check(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_interval = 60.0 / self.rate_limit

        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def lookup(self, phone: str) -> Dict[str, Any]:
        """
        Perform HLR lookup on phone number

        Args:
            phone: Phone number in E.164 format

        Returns:
            HLR information dictionary
        """
        if self.provider == 'hlr-lookups':
            return self._lookup_hlr_lookups(phone)
        elif self.provider == 'nexmo':
            return self._lookup_nexmo(phone)
        elif self.provider == 'twilio':
            return self._lookup_twilio(phone)
        elif self.provider == 'numverify':
            return self._lookup_numverify(phone)
        else:
            return {'error': f'Unknown provider: {self.provider}'}

    def _lookup_hlr_lookups(self, phone: str) -> Dict[str, Any]:
        """Lookup using hlr-lookups.com"""
        try:
            self._rate_limit_check()
            self.logger.info(f"HLR lookup for {phone} via hlr-lookups.com")

            params = {
                'action': 'submitSyncLookupRequest',
                'msisdn': phone.lstrip('+'),
                'username': self.config.get('username'),
                'password': self.api_key
            }

            response = self.session.get(
                self.api_url,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_hlr_lookups_response(data, phone)
            else:
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"HLR lookup error: {e}")
            return {'error': str(e)}

    def _lookup_nexmo(self, phone: str) -> Dict[str, Any]:
        """Lookup using Nexmo/Vonage"""
        try:
            self._rate_limit_check()
            self.logger.info(f"HLR lookup for {phone} via Nexmo")

            params = {
                'api_key': self.config.get('api_key'),
                'api_secret': self.config.get('api_secret'),
                'number': phone.lstrip('+')
            }

            response = self.session.get(
                self.api_url,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_nexmo_response(data, phone)
            else:
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Nexmo lookup error: {e}")
            return {'error': str(e)}

    def _lookup_twilio(self, phone: str) -> Dict[str, Any]:
        """Lookup using Twilio"""
        try:
            self._rate_limit_check()
            self.logger.info(f"HLR lookup for {phone} via Twilio")

            url = f"{self.api_url}/{phone}"
            auth = (self.config.get('account_sid'), self.api_key)

            params = {
                'Type': 'carrier'
            }

            response = self.session.get(
                url,
                auth=auth,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_twilio_response(data, phone)
            else:
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Twilio lookup error: {e}")
            return {'error': str(e)}

    def _lookup_numverify(self, phone: str) -> Dict[str, Any]:
        """Lookup using NumVerify"""
        try:
            self._rate_limit_check()
            self.logger.info(f"HLR lookup for {phone} via NumVerify")

            params = {
                'access_key': self.api_key,
                'number': phone.lstrip('+'),
                'format': 1
            }

            response = self.session.get(
                self.api_url,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_numverify_response(data, phone)
            else:
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"NumVerify lookup error: {e}")
            return {'error': str(e)}

    def _parse_hlr_lookups_response(self, data: Dict[str, Any], phone: str) -> Dict[str, Any]:
        """Parse hlr-lookups.com response"""
        result = {
            'phone': phone,
            'status': 'UNKNOWN',
            'network': {},
            'location': {},
            'roaming': {},
            'imsi': None,
            'ported': False,
            'raw': data
        }

        try:
            if data.get('success'):
                # Status
                result['status'] = data.get('status', 'ACTIVE')

                # Network information
                result['network'] = {
                    'mccmnc': data.get('mccmnc'),
                    'mcc': data.get('mcc'),
                    'mnc': data.get('mnc'),
                    'network_name': data.get('networkName'),
                    'country': data.get('country'),
                    'country_code': data.get('countryCode')
                }

                # IMSI
                result['imsi'] = data.get('imsi')

                # Porting
                result['ported'] = data.get('isPorted', False)

                # Roaming
                if data.get('isRoaming'):
                    result['roaming'] = {
                        'is_roaming': True,
                        'roaming_country': data.get('roamingCountry'),
                        'roaming_network': data.get('roamingNetwork')
                    }

        except Exception as e:
            self.logger.error(f"Error parsing HLR response: {e}")

        return result

    def _parse_nexmo_response(self, data: Dict[str, Any], phone: str) -> Dict[str, Any]:
        """Parse Nexmo response"""
        result = {
            'phone': phone,
            'status': 'ACTIVE' if data.get('status') == 0 else 'UNKNOWN',
            'network': {},
            'location': {},
            'roaming': {},
            'imsi': None,
            'ported': False,
            'raw': data
        }

        if 'current_carrier' in data:
            carrier = data['current_carrier']
            result['network'] = {
                'network_name': carrier.get('name'),
                'network_code': carrier.get('network_code'),
                'country': carrier.get('country'),
                'network_type': carrier.get('network_type')
            }

        if 'original_carrier' in data and data['original_carrier'] != data.get('current_carrier'):
            result['ported'] = True

        return result

    def _parse_twilio_response(self, data: Dict[str, Any], phone: str) -> Dict[str, Any]:
        """Parse Twilio response"""
        result = {
            'phone': phone,
            'status': 'ACTIVE',
            'network': {},
            'location': {},
            'roaming': {},
            'imsi': None,
            'ported': False,
            'raw': data
        }

        if 'carrier' in data:
            carrier = data['carrier']
            result['network'] = {
                'network_name': carrier.get('name'),
                'mobile_country_code': carrier.get('mobile_country_code'),
                'mobile_network_code': carrier.get('mobile_network_code'),
                'type': carrier.get('type')
            }

        return result

    def _parse_numverify_response(self, data: Dict[str, Any], phone: str) -> Dict[str, Any]:
        """Parse NumVerify response"""
        result = {
            'phone': phone,
            'status': 'ACTIVE' if data.get('valid') else 'INVALID',
            'network': {},
            'location': {},
            'roaming': {},
            'imsi': None,
            'ported': False,
            'raw': data
        }

        result['network'] = {
            'network_name': data.get('carrier'),
            'country': data.get('country_name'),
            'country_code': data.get('country_code'),
            'line_type': data.get('line_type')
        }

        result['location'] = {
            'country': data.get('country_name'),
            'location': data.get('location')
        }

        return result

    def is_active(self, phone: str) -> bool:
        """
        Check if number is active on network

        Args:
            phone: Phone number

        Returns:
            True if active, False otherwise
        """
        result = self.lookup(phone)
        return result.get('status') == 'ACTIVE'

    def is_roaming(self, phone: str) -> bool:
        """
        Check if number is currently roaming

        Args:
            phone: Phone number

        Returns:
            True if roaming, False otherwise
        """
        result = self.lookup(phone)
        return result.get('roaming', {}).get('is_roaming', False)

    def is_ported(self, phone: str) -> bool:
        """
        Check if number has been ported

        Args:
            phone: Phone number

        Returns:
            True if ported, False otherwise
        """
        result = self.lookup(phone)
        return result.get('ported', False)

    def get_network_info(self, phone: str) -> Dict[str, Any]:
        """
        Get network information only

        Args:
            phone: Phone number

        Returns:
            Network information dictionary
        """
        result = self.lookup(phone)
        return result.get('network', {})

    def batch_lookup(self, phones: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Batch HLR lookup

        Args:
            phones: List of phone numbers

        Returns:
            Dictionary mapping phone numbers to results
        """
        results = {}

        for phone in phones:
            results[phone] = self.lookup(phone)

        return results


def main():
    """Example usage"""
    # Initialize with API credentials
    hlr = HLRLookup({
        'provider': 'hlr-lookups',
        'api_key': 'YOUR_API_KEY',
        'username': 'YOUR_USERNAME'
    })

    # Lookup phone number
    phone = "+14155552671"
    result = hlr.lookup(phone)

    print(f"HLR Lookup for {phone}:")
    print(json.dumps(result, indent=2))

    # Check status
    if hlr.is_active(phone):
        print(f"\n{phone} is ACTIVE on network")

    # Check roaming
    if hlr.is_roaming(phone):
        print(f"{phone} is currently ROAMING")

    # Check porting
    if hlr.is_ported(phone):
        print(f"{phone} has been PORTED")

    # Get network info
    network = hlr.get_network_info(phone)
    print(f"\nNetwork: {network.get('network_name')}")
    print(f"Country: {network.get('country')}")


if __name__ == "__main__":
    main()
