"""
SMS Intelligence
SMS gateway detection, bulk sender identification, and message pattern analysis
"""

import re
import requests
import json
import logging
from typing import Dict, List, Optional, Any
from collections import Counter
import hashlib


class SMSIntelligence:
    """
    SMS intelligence and analysis system
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize SMS intelligence system

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # SMS gateway databases
        self.known_gateways = self._load_gateway_database()
        self.disposable_providers = self._load_disposable_database()

        # Pattern detection
        self.spam_patterns = self._load_spam_patterns()

        self.logger.info("SMS intelligence initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('SMSIntelligence')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _load_gateway_database(self) -> Dict[str, Dict[str, Any]]:
        """Load SMS gateway database"""
        # Known SMS gateway prefixes and patterns
        return {
            'twilio': {
                'patterns': [r'^\+1\d{10}$'],
                'description': 'Twilio SMS Gateway',
                'type': 'gateway',
                'country': 'US'
            },
            'nexmo': {
                'patterns': [r'^\+\d{10,15}$'],
                'description': 'Nexmo/Vonage SMS',
                'type': 'gateway',
                'country': 'Multiple'
            },
            'bandwidth': {
                'patterns': [r'^\+1\d{10}$'],
                'description': 'Bandwidth SMS',
                'type': 'gateway',
                'country': 'US'
            },
            'plivo': {
                'patterns': [r'^\+\d{10,15}$'],
                'description': 'Plivo SMS',
                'type': 'gateway',
                'country': 'Multiple'
            },
            'clickatell': {
                'patterns': [r'^\+\d{10,15}$'],
                'description': 'Clickatell SMS',
                'type': 'gateway',
                'country': 'Multiple'
            }
        }

    def _load_disposable_database(self) -> List[str]:
        """Load disposable/temporary SMS service database"""
        return [
            'receive-sms-online.info',
            'receivesmsonline.net',
            'receive-sms.com',
            'sms-online.co',
            'receive-a-sms.com',
            'smsreceivefree.com',
            'receivesms.co',
            'temp-number.org',
            'burnerapp.com',
            'hushed.com',
            'textfree.us',
            'textnow.com',
            'pinger.com',
            'freephonenum.com',
            'receivesmsonline.com',
            'sms24.me',
            'receivesmsonline.in',
            'hs3x.com',
            'sellaite.com',
            'freesmsverification.com'
        ]

    def _load_spam_patterns(self) -> List[re.Pattern]:
        """Load SMS spam detection patterns"""
        patterns = [
            r'(?i)click here',
            r'(?i)limited time',
            r'(?i)act now',
            r'(?i)congratulations',
            r'(?i)you.*won',
            r'(?i)free\s+(?:gift|money|prize)',
            r'(?i)call now',
            r'(?i)text\s+\w+\s+to',
            r'(?i)opt[- ]?out',
            r'(?i)unsubscribe',
            r'(?i)reply\s+stop',
            r'(?i)verification\s+code',
            r'(?i)confirm\s+your',
            r'(?i)reset\s+password',
            r'(?i)billing\s+problem',
            r'(?i)account\s+suspended',
            r'(?i)urgent\s+action',
            r'(?i)expire[ds]?\s+(?:soon|today)',
            r'https?://[^\s]+',  # URLs
            r'\$\d+',  # Money amounts
        ]

        return [re.compile(p) for p in patterns]

    def analyze(self, phone: str) -> Dict[str, Any]:
        """
        Analyze phone number for SMS-related characteristics

        Args:
            phone: Phone number in E.164 format

        Returns:
            SMS intelligence dictionary
        """
        result = {
            'phone': phone,
            'is_sms_gateway': False,
            'gateway_provider': None,
            'is_disposable': False,
            'disposable_service': None,
            'is_bulk_sender': False,
            'sender_reputation': 'UNKNOWN',
            'characteristics': [],
            'warnings': []
        }

        # Check if SMS gateway
        gateway_info = self._detect_gateway(phone)
        if gateway_info:
            result['is_sms_gateway'] = True
            result['gateway_provider'] = gateway_info.get('provider')
            result['characteristics'].append('SMS Gateway')

        # Check if disposable
        if self._is_disposable(phone):
            result['is_disposable'] = True
            result['characteristics'].append('Disposable/Temporary')
            result['warnings'].append('Number may be from temporary SMS service')

        # Check bulk sender indicators
        if self._is_bulk_sender(phone):
            result['is_bulk_sender'] = True
            result['characteristics'].append('Bulk Sender')

        # Reputation check
        result['sender_reputation'] = self._check_reputation(phone)

        return result

    def _detect_gateway(self, phone: str) -> Optional[Dict[str, Any]]:
        """Detect if number is from SMS gateway"""
        # Note: Actual gateway detection requires database/API access
        # This is pattern-based detection

        for gateway_name, gateway_info in self.known_gateways.items():
            for pattern in gateway_info['patterns']:
                if re.match(pattern, phone):
                    # Additional checks could be done here
                    return {
                        'provider': gateway_name,
                        'description': gateway_info['description'],
                        'type': gateway_info['type']
                    }

        return None

    def _is_disposable(self, phone: str) -> bool:
        """Check if number is from disposable SMS service"""
        # This would typically involve:
        # 1. Checking against known disposable number ranges
        # 2. API lookup to disposable SMS databases
        # 3. Pattern matching against known providers

        # Placeholder implementation
        # In production, this would query a database or API

        return False

    def _is_bulk_sender(self, phone: str) -> bool:
        """Detect if number is used for bulk SMS sending"""
        # Indicators of bulk sending:
        # 1. Short code (5-6 digit numbers)
        # 2. Alphanumeric sender ID
        # 3. Known marketing number ranges

        digits_only = re.sub(r'[^\d]', '', phone)

        # Short codes (US)
        if len(digits_only) == 5 or len(digits_only) == 6:
            return True

        # Toll-free numbers often used for bulk SMS
        if digits_only.startswith('1800') or digits_only.startswith('1888'):
            return True

        return False

    def _check_reputation(self, phone: str) -> str:
        """
        Check sender reputation

        Returns:
            Reputation level: GOOD, NEUTRAL, POOR, SPAM, UNKNOWN
        """
        # This would typically involve:
        # 1. Checking spam databases
        # 2. Analyzing complaint rates
        # 3. Looking up in SMS reputation services

        # Placeholder - would integrate with actual reputation services
        return 'UNKNOWN'

    def analyze_message(self, message: str) -> Dict[str, Any]:
        """
        Analyze SMS message content

        Args:
            message: SMS message text

        Returns:
            Message analysis dictionary
        """
        result = {
            'message_length': len(message),
            'spam_score': 0,
            'is_likely_spam': False,
            'patterns_found': [],
            'contains_url': False,
            'contains_phone': False,
            'message_type': 'UNKNOWN',
            'warnings': []
        }

        # Check for spam patterns
        spam_indicators = 0
        for pattern in self.spam_patterns:
            if pattern.search(message):
                spam_indicators += 1
                result['patterns_found'].append(pattern.pattern)

        result['spam_score'] = min(spam_indicators * 10, 100)
        result['is_likely_spam'] = result['spam_score'] > 50

        # Check for URLs
        if re.search(r'https?://[^\s]+', message):
            result['contains_url'] = True
            result['warnings'].append('Message contains URL')

        # Check for phone numbers
        if re.search(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', message):
            result['contains_phone'] = True

        # Classify message type
        result['message_type'] = self._classify_message(message)

        return result

    def _classify_message(self, message: str) -> str:
        """Classify SMS message type"""
        message_lower = message.lower()

        # OTP/Verification
        if any(word in message_lower for word in ['code', 'verification', 'otp', 'verify']):
            return 'VERIFICATION'

        # Marketing
        if any(word in message_lower for word in ['sale', 'offer', 'discount', 'deal']):
            return 'MARKETING'

        # Alert
        if any(word in message_lower for word in ['alert', 'warning', 'urgent', 'important']):
            return 'ALERT'

        # Transactional
        if any(word in message_lower for word in ['transaction', 'payment', 'receipt', 'order']):
            return 'TRANSACTIONAL'

        # Personal
        return 'PERSONAL'

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

    def detect_campaign(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Detect SMS campaign patterns

        Args:
            messages: List of message dictionaries with 'sender', 'text', 'timestamp'

        Returns:
            Campaign detection results
        """
        result = {
            'is_campaign': False,
            'campaign_size': len(messages),
            'unique_senders': 0,
            'common_patterns': [],
            'time_distribution': {},
            'sender_analysis': {}
        }

        if not messages:
            return result

        # Analyze senders
        senders = [msg['sender'] for msg in messages]
        sender_counts = Counter(senders)
        result['unique_senders'] = len(sender_counts)

        # If same sender to multiple recipients, likely campaign
        if sender_counts.most_common(1)[0][1] > 5:
            result['is_campaign'] = True

        # Analyze message similarity
        message_texts = [msg.get('text', '') for msg in messages]
        similarities = self._calculate_message_similarity(message_texts)

        if similarities['average_similarity'] > 0.7:
            result['is_campaign'] = True
            result['common_patterns'] = similarities['common_phrases']

        return result

    def _calculate_message_similarity(self, messages: List[str]) -> Dict[str, Any]:
        """Calculate similarity between messages"""
        result = {
            'average_similarity': 0.0,
            'common_phrases': []
        }

        if len(messages) < 2:
            return result

        # Extract common phrases (3+ words)
        phrases = []
        for message in messages:
            words = message.lower().split()
            for i in range(len(words) - 2):
                phrase = ' '.join(words[i:i+3])
                phrases.append(phrase)

        phrase_counts = Counter(phrases)
        common = phrase_counts.most_common(5)

        result['common_phrases'] = [phrase for phrase, count in common if count > 1]

        # Simple similarity metric
        if phrases:
            unique_phrases = len(set(phrases))
            total_phrases = len(phrases)
            result['average_similarity'] = 1.0 - (unique_phrases / total_phrases)

        return result

    def generate_message_fingerprint(self, message: str) -> str:
        """
        Generate fingerprint for message deduplication

        Args:
            message: SMS message text

        Returns:
            Message fingerprint hash
        """
        # Normalize message
        normalized = re.sub(r'\s+', ' ', message.lower().strip())
        normalized = re.sub(r'\d+', 'N', normalized)  # Replace numbers

        # Generate hash
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def main():
    """Example usage"""
    sms = SMSIntelligence()

    # Analyze phone number
    phone = "+14155552671"
    result = sms.analyze(phone)

    print(f"SMS Analysis for {phone}:")
    print(json.dumps(result, indent=2))

    # Analyze message content
    message = "URGENT: Click here to claim your FREE prize! Limited time offer. Reply STOP to unsubscribe."
    msg_analysis = sms.analyze_message(message)

    print(f"\nMessage Analysis:")
    print(f"Spam Score: {msg_analysis['spam_score']}/100")
    print(f"Type: {msg_analysis['message_type']}")
    print(f"Likely Spam: {msg_analysis['is_likely_spam']}")

    # Generate fingerprint
    fingerprint = sms.generate_message_fingerprint(message)
    print(f"\nMessage Fingerprint: {fingerprint}")

    # Detect campaign
    messages = [
        {'sender': '+14155551234', 'text': 'Special offer just for you!', 'timestamp': '2024-01-01'},
        {'sender': '+14155551234', 'text': 'Special offer just for you!', 'timestamp': '2024-01-01'},
        {'sender': '+14155551234', 'text': 'Special offer just for you!', 'timestamp': '2024-01-01'},
    ]

    campaign = sms.detect_campaign(messages)
    print(f"\nCampaign Detection:")
    print(f"Is Campaign: {campaign['is_campaign']}")
    print(f"Unique Senders: {campaign['unique_senders']}")


if __name__ == "__main__":
    main()
