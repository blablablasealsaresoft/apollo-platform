"""
Phone Geolocation Module
Phone number intelligence and geolocation
"""

import logging
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from typing import Dict, Optional, List
import json
from datetime import datetime


class PhoneGeolocation:
    """Phone Number Geolocation and Intelligence"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize Phone Geolocation module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys for premium services
        self.numverify_key = self.config.get('numverify_key')
        self.numlookup_key = self.config.get('numlookup_key')
        self.twilio_sid = self.config.get('twilio_sid')
        self.twilio_token = self.config.get('twilio_token')

        # Cache
        self.cache = {}

    def geolocate(self, phone_number: str, country_code: Optional[str] = None) -> Dict:
        """
        Geolocate phone number and gather intelligence

        Args:
            phone_number: Phone number to analyze
            country_code: Optional country code (e.g., 'US')

        Returns:
            Dictionary with phone intelligence
        """
        # Check cache
        if phone_number in self.cache:
            return self.cache[phone_number]

        result = {
            'phone_number': phone_number,
            'timestamp': datetime.now().isoformat(),
            'is_valid': False,
            'location': {},
            'carrier_info': {},
            'type': None,
            'timezone': [],
            'formatted': {}
        }

        try:
            # Parse phone number
            parsed = self._parse_number(phone_number, country_code)
            if not parsed:
                return result

            result['is_valid'] = phonenumbers.is_valid_number(parsed)
            result['is_possible'] = phonenumbers.is_possible_number(parsed)

            # Get location
            result['location'] = self._get_location(parsed)

            # Get carrier information
            result['carrier_info'] = self._get_carrier(parsed)

            # Get number type
            result['type'] = self._get_number_type(parsed)

            # Get timezone
            result['timezone'] = self._get_timezone(parsed)

            # Format variations
            result['formatted'] = self._format_number(parsed)

            # Query premium APIs if available
            if self.numverify_key:
                numverify_data = self._query_numverify(phone_number)
                result['numverify'] = numverify_data

            if self.numlookup_key:
                numlookup_data = self._query_numlookup(phone_number)
                result['numlookup'] = numlookup_data

            if self.twilio_sid and self.twilio_token:
                twilio_data = self._query_twilio(phone_number)
                result['twilio'] = twilio_data

            # HLR lookup (if configured)
            if self.config.get('enable_hlr'):
                result['hlr'] = self._hlr_lookup(phone_number)

        except Exception as e:
            self.logger.error(f"Phone geolocation error: {e}")
            result['error'] = str(e)

        # Cache result
        self.cache[phone_number] = result

        return result

    def _parse_number(self, phone_number: str, country_code: Optional[str] = None) -> Optional[phonenumbers.PhoneNumber]:
        """Parse phone number"""
        try:
            return phonenumbers.parse(phone_number, country_code)
        except phonenumbers.NumberParseException as e:
            self.logger.error(f"Failed to parse phone number: {e}")
            return None

    def _get_location(self, parsed: phonenumbers.PhoneNumber) -> Dict:
        """Get geographic location from phone number"""
        try:
            location_desc = geocoder.description_for_number(parsed, "en")
            country_code = phonenumbers.region_code_for_number(parsed)

            return {
                'description': location_desc,
                'country': self._get_country_name(country_code),
                'country_code': country_code,
                'region': location_desc
            }
        except Exception as e:
            self.logger.error(f"Location lookup error: {e}")
            return {}

    def _get_carrier(self, parsed: phonenumbers.PhoneNumber) -> Dict:
        """Get carrier information"""
        try:
            carrier_name = carrier.name_for_number(parsed, "en")

            return {
                'name': carrier_name,
                'type': 'mobile' if carrier_name else 'landline'
            }
        except Exception as e:
            self.logger.error(f"Carrier lookup error: {e}")
            return {}

    def _get_number_type(self, parsed: phonenumbers.PhoneNumber) -> str:
        """Get phone number type"""
        try:
            number_type = phonenumbers.number_type(parsed)

            type_map = {
                phonenumbers.PhoneNumberType.MOBILE: 'mobile',
                phonenumbers.PhoneNumberType.FIXED_LINE: 'fixed_line',
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'fixed_line_or_mobile',
                phonenumbers.PhoneNumberType.TOLL_FREE: 'toll_free',
                phonenumbers.PhoneNumberType.PREMIUM_RATE: 'premium_rate',
                phonenumbers.PhoneNumberType.SHARED_COST: 'shared_cost',
                phonenumbers.PhoneNumberType.VOIP: 'voip',
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'personal_number',
                phonenumbers.PhoneNumberType.PAGER: 'pager',
                phonenumbers.PhoneNumberType.UAN: 'uan',
                phonenumbers.PhoneNumberType.VOICEMAIL: 'voicemail',
                phonenumbers.PhoneNumberType.UNKNOWN: 'unknown'
            }

            return type_map.get(number_type, 'unknown')
        except Exception as e:
            self.logger.error(f"Number type lookup error: {e}")
            return 'unknown'

    def _get_timezone(self, parsed: phonenumbers.PhoneNumber) -> List[str]:
        """Get timezone(s) for phone number"""
        try:
            return timezone.time_zones_for_number(parsed)
        except Exception as e:
            self.logger.error(f"Timezone lookup error: {e}")
            return []

    def _format_number(self, parsed: phonenumbers.PhoneNumber) -> Dict:
        """Format phone number in various formats"""
        try:
            return {
                'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                'rfc3966': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966)
            }
        except Exception as e:
            self.logger.error(f"Number formatting error: {e}")
            return {}

    def _get_country_name(self, country_code: str) -> str:
        """Get full country name from code"""
        country_map = {
            'US': 'United States',
            'GB': 'United Kingdom',
            'CA': 'Canada',
            'AU': 'Australia',
            'DE': 'Germany',
            'FR': 'France',
            'IT': 'Italy',
            'ES': 'Spain',
            'JP': 'Japan',
            'CN': 'China',
            'IN': 'India',
            'BR': 'Brazil',
            'MX': 'Mexico',
            'RU': 'Russia',
            'KR': 'South Korea'
        }
        return country_map.get(country_code, country_code)

    def _query_numverify(self, phone_number: str) -> Dict:
        """Query Numverify API"""
        try:
            url = "http://apilayer.net/api/validate"
            params = {
                'access_key': self.numverify_key,
                'number': phone_number,
                'country_code': '',
                'format': 1
            }

            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'valid': data.get('valid'),
                'number': data.get('number'),
                'local_format': data.get('local_format'),
                'international_format': data.get('international_format'),
                'country_prefix': data.get('country_prefix'),
                'country_code': data.get('country_code'),
                'country_name': data.get('country_name'),
                'location': data.get('location'),
                'carrier': data.get('carrier'),
                'line_type': data.get('line_type')
            }
        except Exception as e:
            self.logger.error(f"Numverify query error: {e}")
            return {}

    def _query_numlookup(self, phone_number: str) -> Dict:
        """Query NumLookup API"""
        try:
            url = f"https://api.numlookupapi.com/v1/validate/{phone_number}"
            headers = {'apikey': self.numlookup_key}

            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'valid': data.get('valid'),
                'number': data.get('number'),
                'country_code': data.get('country_code'),
                'country_name': data.get('country_name'),
                'location': data.get('location'),
                'carrier': data.get('carrier'),
                'line_type': data.get('line_type')
            }
        except Exception as e:
            self.logger.error(f"NumLookup query error: {e}")
            return {}

    def _query_twilio(self, phone_number: str) -> Dict:
        """Query Twilio Lookup API"""
        try:
            from twilio.rest import Client

            client = Client(self.twilio_sid, self.twilio_token)

            # Lookup with carrier and caller name
            number = client.lookups.v1.phone_numbers(phone_number).fetch(
                type=['carrier', 'caller-name']
            )

            return {
                'phone_number': number.phone_number,
                'country_code': number.country_code,
                'carrier': {
                    'name': number.carrier.get('name'),
                    'type': number.carrier.get('type'),
                    'mobile_country_code': number.carrier.get('mobile_country_code'),
                    'mobile_network_code': number.carrier.get('mobile_network_code')
                } if number.carrier else {},
                'caller_name': number.caller_name.get('caller_name') if number.caller_name else None
            }
        except Exception as e:
            self.logger.error(f"Twilio lookup error: {e}")
            return {}

    def _hlr_lookup(self, phone_number: str) -> Dict:
        """
        Home Location Register (HLR) lookup
        Determines if number is active and roaming status
        """
        try:
            # This requires a premium HLR service
            # Placeholder for HLR integration
            if self.config.get('hlr_api_key'):
                url = f"https://api.hlrlookup.com/v1/lookup"
                headers = {'Authorization': f"Bearer {self.config['hlr_api_key']}"}
                data = {'msisdn': phone_number}

                response = requests.post(url, headers=headers, json=data, timeout=10)
                response.raise_for_status()
                hlr_data = response.json()

                return {
                    'status': hlr_data.get('status'),
                    'imsi': hlr_data.get('imsi'),
                    'mccmnc': hlr_data.get('mccmnc'),
                    'mcc': hlr_data.get('mcc'),
                    'mnc': hlr_data.get('mnc'),
                    'roaming': hlr_data.get('roaming'),
                    'ported': hlr_data.get('ported'),
                    'original_network': hlr_data.get('original_network'),
                    'current_network': hlr_data.get('current_network')
                }
        except Exception as e:
            self.logger.error(f"HLR lookup error: {e}")

        return {}

    def check_portability(self, phone_number: str) -> Dict:
        """
        Check if number has been ported between carriers

        Args:
            phone_number: Phone number to check

        Returns:
            Portability information
        """
        result = {
            'number': phone_number,
            'is_ported': False,
            'original_carrier': None,
            'current_carrier': None,
            'port_date': None
        }

        try:
            # This would integrate with LNP (Local Number Portability) database
            # Placeholder for actual implementation
            if self.config.get('lnp_api_key'):
                url = "https://api.lnp.example.com/check"
                headers = {'Authorization': f"Bearer {self.config['lnp_api_key']}"}
                params = {'number': phone_number}

                response = requests.get(url, headers=headers, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()

                result.update(data)
        except Exception as e:
            self.logger.error(f"Portability check error: {e}")

        return result

    def batch_lookup(self, phone_numbers: List[str]) -> List[Dict]:
        """Batch lookup multiple phone numbers"""
        results = []
        for number in phone_numbers:
            try:
                result = self.geolocate(number)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch lookup failed for {number}: {e}")
                results.append({'phone_number': number, 'error': str(e)})
        return results

    def validate_number(self, phone_number: str, country_code: Optional[str] = None) -> bool:
        """
        Validate if phone number is valid

        Args:
            phone_number: Phone number to validate
            country_code: Optional country code

        Returns:
            True if valid, False otherwise
        """
        try:
            parsed = self._parse_number(phone_number, country_code)
            return phonenumbers.is_valid_number(parsed) if parsed else False
        except Exception:
            return False


if __name__ == "__main__":
    # Example usage
    phone_geo = PhoneGeolocation({
        'numverify_key': 'your_key_here'
    })

    # Geolocate phone number
    result = phone_geo.geolocate("+1-555-0123")
    print(json.dumps(result, indent=2))

    # Validate number
    is_valid = phone_geo.validate_number("+14155552671")
    print(f"Number valid: {is_valid}")
