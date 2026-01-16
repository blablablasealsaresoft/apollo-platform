"""
VoIP Intelligence
VoIP number identification and provider detection
"""

import re
import requests
import json
import logging
from typing import Dict, List, Optional, Any
import phonenumbers


class VoIPIntelligence:
    """
    VoIP number detection and intelligence system
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize VoIP intelligence system

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # VoIP provider database
        self.voip_providers = self._load_voip_providers()

        # Number range databases
        self.voip_ranges = self._load_voip_ranges()

        self.logger.info("VoIP intelligence initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('VoIPIntelligence')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _load_voip_providers(self) -> Dict[str, Dict[str, Any]]:
        """Load VoIP provider database"""
        return {
            'skype': {
                'name': 'Skype',
                'type': 'voip',
                'patterns': [r'^\+99\d+'],  # Skype uses +99 prefix
                'description': 'Microsoft Skype',
                'features': ['voice', 'video', 'messaging']
            },
            'google_voice': {
                'name': 'Google Voice',
                'type': 'voip',
                'patterns': [],  # Uses regular US numbers
                'description': 'Google Voice',
                'features': ['voice', 'sms', 'voicemail']
            },
            'vonage': {
                'name': 'Vonage',
                'type': 'voip',
                'patterns': [],
                'description': 'Vonage VoIP Service',
                'features': ['voice', 'sms']
            },
            'ringcentral': {
                'name': 'RingCentral',
                'type': 'voip',
                'patterns': [],
                'description': 'RingCentral Business VoIP',
                'features': ['voice', 'sms', 'fax', 'video']
            },
            'magicjack': {
                'name': 'magicJack',
                'type': 'voip',
                'patterns': [],
                'description': 'magicJack VoIP',
                'features': ['voice']
            },
            'ooma': {
                'name': 'Ooma',
                'type': 'voip',
                'patterns': [],
                'description': 'Ooma VoIP',
                'features': ['voice']
            },
            'grasshopper': {
                'name': 'Grasshopper',
                'type': 'voip',
                'patterns': [],
                'description': 'Grasshopper Virtual Phone',
                'features': ['voice', 'sms']
            },
            'zoom': {
                'name': 'Zoom Phone',
                'type': 'voip',
                'patterns': [],
                'description': 'Zoom Phone System',
                'features': ['voice', 'sms', 'video']
            },
            'cisco_webex': {
                'name': 'Cisco Webex Calling',
                'type': 'voip',
                'patterns': [],
                'description': 'Cisco Webex VoIP',
                'features': ['voice', 'video', 'messaging']
            },
            'dialpad': {
                'name': 'Dialpad',
                'type': 'voip',
                'patterns': [],
                'description': 'Dialpad Business Communications',
                'features': ['voice', 'sms', 'video']
            },
            'nextiva': {
                'name': 'Nextiva',
                'type': 'voip',
                'patterns': [],
                'description': 'Nextiva VoIP',
                'features': ['voice', 'sms', 'video']
            },
            '8x8': {
                'name': '8x8',
                'type': 'voip',
                'patterns': [],
                'description': '8x8 Cloud Communications',
                'features': ['voice', 'video', 'messaging']
            },
            'whatsapp': {
                'name': 'WhatsApp',
                'type': 'messaging_voip',
                'patterns': [],
                'description': 'WhatsApp Voice Calling',
                'features': ['voice', 'video', 'messaging']
            },
            'telegram': {
                'name': 'Telegram',
                'type': 'messaging_voip',
                'patterns': [],
                'description': 'Telegram Voice Calling',
                'features': ['voice', 'messaging']
            },
            'viber': {
                'name': 'Viber',
                'type': 'messaging_voip',
                'patterns': [],
                'description': 'Viber Voice/Video',
                'features': ['voice', 'video', 'messaging']
            },
            'discord': {
                'name': 'Discord',
                'type': 'messaging_voip',
                'patterns': [],
                'description': 'Discord Voice',
                'features': ['voice', 'video', 'messaging']
            }
        }

    def _load_voip_ranges(self) -> List[Dict[str, Any]]:
        """Load known VoIP number ranges"""
        return [
            {
                'prefix': '+99',
                'provider': 'skype',
                'description': 'Skype Online Numbers'
            },
            # Add more known VoIP ranges
        ]

    def analyze(self, phone: str) -> Dict[str, Any]:
        """
        Analyze if phone number is VoIP

        Args:
            phone: Phone number in E.164 format

        Returns:
            VoIP analysis dictionary
        """
        result = {
            'phone': phone,
            'is_voip': False,
            'confidence': 0.0,
            'provider': None,
            'provider_type': None,
            'detection_methods': [],
            'features': [],
            'characteristics': []
        }

        # Method 1: Pattern matching
        pattern_match = self._check_patterns(phone)
        if pattern_match:
            result['is_voip'] = True
            result['provider'] = pattern_match['provider']
            result['confidence'] = 0.9
            result['detection_methods'].append('pattern_match')

        # Method 2: Number type detection
        number_type_check = self._check_number_type(phone)
        if number_type_check['is_voip']:
            result['is_voip'] = True
            result['detection_methods'].append('number_type')
            if result['confidence'] < 0.8:
                result['confidence'] = 0.8

        # Method 3: Carrier lookup
        carrier_check = self._check_carrier(phone)
        if carrier_check['is_voip']:
            result['is_voip'] = True
            result['provider'] = carrier_check.get('provider')
            result['detection_methods'].append('carrier_lookup')
            if result['confidence'] < 0.7:
                result['confidence'] = 0.7

        # Method 4: Range database
        range_check = self._check_range_database(phone)
        if range_check:
            result['is_voip'] = True
            result['provider'] = range_check['provider']
            result['detection_methods'].append('range_database')
            result['confidence'] = max(result['confidence'], 0.95)

        # Add provider details
        if result['provider']:
            provider_info = self.voip_providers.get(result['provider'], {})
            result['provider_type'] = provider_info.get('type')
            result['features'] = provider_info.get('features', [])

        # Add characteristics
        if result['is_voip']:
            result['characteristics'] = self._analyze_characteristics(phone, result)

        return result

    def _check_patterns(self, phone: str) -> Optional[Dict[str, str]]:
        """Check phone number against VoIP patterns"""
        for provider_id, provider_info in self.voip_providers.items():
            for pattern in provider_info['patterns']:
                if re.match(pattern, phone):
                    return {
                        'provider': provider_id,
                        'name': provider_info['name']
                    }
        return None

    def _check_number_type(self, phone: str) -> Dict[str, Any]:
        """Check number type using phonenumbers library"""
        result = {'is_voip': False}

        try:
            parsed = phonenumbers.parse(phone)
            number_type = phonenumbers.number_type(parsed)

            if number_type == phonenumbers.PhoneNumberType.VOIP:
                result['is_voip'] = True

        except Exception as e:
            self.logger.error(f"Error checking number type: {e}")

        return result

    def _check_carrier(self, phone: str) -> Dict[str, Any]:
        """Check carrier information for VoIP indicators"""
        result = {'is_voip': False}

        try:
            parsed = phonenumbers.parse(phone)
            carrier_name = phonenumbers.carrier.name_for_number(parsed, 'en')

            if carrier_name:
                carrier_lower = carrier_name.lower()

                # Check for VoIP keywords in carrier name
                voip_keywords = [
                    'voip', 'voice', 'ip', 'virtual', 'cloud',
                    'skype', 'google', 'vonage', 'ringcentral',
                    'twilio', 'bandwidth', 'nexmo'
                ]

                for keyword in voip_keywords:
                    if keyword in carrier_lower:
                        result['is_voip'] = True
                        result['provider'] = carrier_name
                        break

        except Exception as e:
            self.logger.error(f"Error checking carrier: {e}")

        return result

    def _check_range_database(self, phone: str) -> Optional[Dict[str, str]]:
        """Check against VoIP number range database"""
        for range_info in self.voip_ranges:
            if phone.startswith(range_info['prefix']):
                return range_info
        return None

    def _analyze_characteristics(self, phone: str, voip_info: Dict[str, Any]) -> List[str]:
        """Analyze VoIP number characteristics"""
        characteristics = []

        # Based on provider
        provider = voip_info.get('provider')
        if provider:
            provider_info = self.voip_providers.get(provider, {})

            if 'voice' in provider_info.get('features', []):
                characteristics.append('Voice Calling Supported')

            if 'video' in provider_info.get('features', []):
                characteristics.append('Video Calling Supported')

            if 'sms' in provider_info.get('features', []):
                characteristics.append('SMS Supported')

            if 'messaging' in provider_info.get('features', []):
                characteristics.append('Messaging Supported')

            provider_type = provider_info.get('type')
            if provider_type == 'messaging_voip':
                characteristics.append('Messaging App with VoIP')
            elif provider_type == 'voip':
                characteristics.append('Dedicated VoIP Service')

        return characteristics

    def check_skype(self, phone: str) -> Dict[str, Any]:
        """
        Specific check for Skype numbers

        Args:
            phone: Phone number

        Returns:
            Skype detection result
        """
        result = {
            'is_skype': False,
            'skype_type': None
        }

        # Skype numbers start with +99
        if phone.startswith('+99'):
            result['is_skype'] = True
            result['skype_type'] = 'skype_online_number'

        return result

    def check_google_voice(self, phone: str) -> Dict[str, Any]:
        """
        Check for Google Voice numbers

        Args:
            phone: Phone number

        Returns:
            Google Voice detection result
        """
        result = {
            'is_google_voice': False,
            'confidence': 0.0
        }

        # Google Voice uses regular US numbers
        # Detection is difficult without database access
        # This would require integration with Google Voice API or database

        try:
            parsed = phonenumbers.parse(phone)
            carrier_name = phonenumbers.carrier.name_for_number(parsed, 'en')

            if carrier_name and 'google' in carrier_name.lower():
                result['is_google_voice'] = True
                result['confidence'] = 0.8

        except:
            pass

        return result

    def batch_analyze(self, phones: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Batch analyze multiple phone numbers

        Args:
            phones: List of phone numbers

        Returns:
            Dictionary mapping phones to analysis results
        """
        results = {}

        for phone in phones:
            results[phone] = self.analyze(phone)

        return results

    def get_voip_providers_list(self) -> List[Dict[str, str]]:
        """
        Get list of supported VoIP providers

        Returns:
            List of provider information
        """
        providers = []

        for provider_id, info in self.voip_providers.items():
            providers.append({
                'id': provider_id,
                'name': info['name'],
                'type': info['type'],
                'description': info['description'],
                'features': info['features']
            })

        return providers

    def is_voip(self, phone: str) -> bool:
        """
        Quick VoIP check

        Args:
            phone: Phone number

        Returns:
            True if VoIP, False otherwise
        """
        result = self.analyze(phone)
        return result['is_voip']


def main():
    """Example usage"""
    voip = VoIPIntelligence()

    # Analyze phone number
    phone = "+14155552671"
    result = voip.analyze(phone)

    print(f"VoIP Analysis for {phone}:")
    print(json.dumps(result, indent=2))

    # Check Skype
    skype_number = "+991234567890"
    skype_result = voip.check_skype(skype_number)
    print(f"\nSkype Check for {skype_number}:")
    print(json.dumps(skype_result, indent=2))

    # Quick check
    if voip.is_voip(phone):
        print(f"\n{phone} is a VoIP number")
    else:
        print(f"\n{phone} is not detected as VoIP")

    # Get providers list
    providers = voip.get_voip_providers_list()
    print(f"\nSupported VoIP providers: {len(providers)}")
    for provider in providers[:5]:
        print(f"  - {provider['name']}: {provider['description']}")


if __name__ == "__main__":
    main()
