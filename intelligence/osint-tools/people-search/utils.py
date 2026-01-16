"""
Utility Functions - People Search & Background Intelligence
Common helper functions used across all modules
"""

import re
import hashlib
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class NameParser:
    """Parse and normalize person names"""

    @staticmethod
    def parse_full_name(full_name: str) -> Dict[str, str]:
        """
        Parse full name into components

        Args:
            full_name: Full name string

        Returns:
            Dictionary with first, middle, last, suffix
        """
        suffixes = ['jr', 'sr', 'ii', 'iii', 'iv', 'v', 'phd', 'md', 'esq']

        parts = full_name.strip().split()

        result = {
            'first': '',
            'middle': '',
            'last': '',
            'suffix': ''
        }

        if not parts:
            return result

        # Check for suffix
        if parts[-1].lower().replace('.', '') in suffixes:
            result['suffix'] = parts[-1]
            parts = parts[:-1]

        if len(parts) == 1:
            result['first'] = parts[0]
        elif len(parts) == 2:
            result['first'] = parts[0]
            result['last'] = parts[1]
        elif len(parts) >= 3:
            result['first'] = parts[0]
            result['middle'] = ' '.join(parts[1:-1])
            result['last'] = parts[-1]

        return result

    @staticmethod
    def normalize_name(name: str) -> str:
        """
        Normalize name for comparison

        Args:
            name: Name to normalize

        Returns:
            Normalized name
        """
        # Remove special characters
        name = re.sub(r'[^a-zA-Z\s]', '', name)

        # Convert to lowercase
        name = name.lower()

        # Remove extra whitespace
        name = ' '.join(name.split())

        return name

    @staticmethod
    def generate_name_variations(name: str) -> List[str]:
        """
        Generate common name variations

        Args:
            name: Full name

        Returns:
            List of name variations
        """
        variations = [name]
        parsed = NameParser.parse_full_name(name)

        if parsed['first'] and parsed['last']:
            # First Last
            variations.append(f"{parsed['first']} {parsed['last']}")

            # Last, First
            variations.append(f"{parsed['last']}, {parsed['first']}")

            # First Middle Last
            if parsed['middle']:
                variations.append(f"{parsed['first']} {parsed['middle']} {parsed['last']}")

            # F. Last
            variations.append(f"{parsed['first'][0]}. {parsed['last']}")

            # First M. Last
            if parsed['middle']:
                variations.append(f"{parsed['first']} {parsed['middle'][0]}. {parsed['last']}")

        return list(set(variations))


class PhoneParser:
    """Parse and normalize phone numbers"""

    @staticmethod
    def normalize_phone(phone: str) -> str:
        """
        Normalize phone number to digits only

        Args:
            phone: Phone number string

        Returns:
            Digits-only phone number
        """
        return re.sub(r'\D', '', phone)

    @staticmethod
    def format_phone(phone: str, format: str = 'national') -> str:
        """
        Format phone number

        Args:
            phone: Phone number
            format: Format type (national, international, dots)

        Returns:
            Formatted phone number
        """
        digits = PhoneParser.normalize_phone(phone)

        if len(digits) == 10:
            if format == 'national':
                return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
            elif format == 'international':
                return f"+1-{digits[:3]}-{digits[3:6]}-{digits[6:]}"
            elif format == 'dots':
                return f"{digits[:3]}.{digits[3:6]}.{digits[6:]}"

        return phone

    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        """
        Extract phone numbers from text

        Args:
            text: Text to search

        Returns:
            List of found phone numbers
        """
        patterns = [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # 123-456-7890
            r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',     # (123) 456-7890
            r'\+1[-.]?\d{3}[-.]?\d{3}[-.]?\d{4}' # +1-123-456-7890
        ]

        phones = []
        for pattern in patterns:
            phones.extend(re.findall(pattern, text))

        return list(set([PhoneParser.normalize_phone(p) for p in phones]))


class EmailParser:
    """Parse and validate email addresses"""

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """
        Validate email address format

        Args:
            email: Email address

        Returns:
            True if valid format
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """
        Extract email addresses from text

        Args:
            text: Text to search

        Returns:
            List of found email addresses
        """
        pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        return re.findall(pattern, text)

    @staticmethod
    def get_domain(email: str) -> Optional[str]:
        """
        Extract domain from email address

        Args:
            email: Email address

        Returns:
            Domain name
        """
        if '@' in email:
            return email.split('@')[1]
        return None


class AddressParser:
    """Parse and normalize addresses"""

    @staticmethod
    def normalize_address(address: str) -> str:
        """
        Normalize address for comparison

        Args:
            address: Address string

        Returns:
            Normalized address
        """
        # Convert to uppercase
        address = address.upper()

        # Standardize abbreviations
        replacements = {
            'STREET': 'ST',
            'AVENUE': 'AVE',
            'ROAD': 'RD',
            'DRIVE': 'DR',
            'BOULEVARD': 'BLVD',
            'LANE': 'LN',
            'COURT': 'CT',
            'CIRCLE': 'CIR',
            'NORTH': 'N',
            'SOUTH': 'S',
            'EAST': 'E',
            'WEST': 'W',
            'APARTMENT': 'APT',
            'SUITE': 'STE',
        }

        for full, abbr in replacements.items():
            address = address.replace(full, abbr)

        # Remove extra whitespace
        address = ' '.join(address.split())

        return address

    @staticmethod
    def parse_address(address: str) -> Dict[str, str]:
        """
        Parse address into components

        Args:
            address: Full address string

        Returns:
            Dictionary with street, city, state, zip
        """
        result = {
            'street': '',
            'city': '',
            'state': '',
            'zip': ''
        }

        # Extract ZIP code
        zip_match = re.search(r'\b\d{5}(?:-\d{4})?\b', address)
        if zip_match:
            result['zip'] = zip_match.group()
            address = address.replace(result['zip'], '').strip()

        # Split by comma
        parts = [p.strip() for p in address.split(',')]

        if len(parts) >= 3:
            result['street'] = parts[0]
            result['city'] = parts[1]
            # State might be in last part
            state_match = re.search(r'\b[A-Z]{2}\b', parts[-1])
            if state_match:
                result['state'] = state_match.group()
        elif len(parts) == 2:
            result['street'] = parts[0]
            result['city'] = parts[1]

        return result


class DataHasher:
    """Generate hashes for data deduplication"""

    @staticmethod
    def hash_person(name: str, dob: Optional[str] = None) -> str:
        """
        Generate unique hash for a person

        Args:
            name: Person's name
            dob: Date of birth

        Returns:
            SHA256 hash
        """
        data = f"{NameParser.normalize_name(name)}:{dob or ''}"
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_profile(platform: str, username: str) -> str:
        """
        Generate unique hash for a social profile

        Args:
            platform: Platform name
            username: Username

        Returns:
            SHA256 hash
        """
        data = f"{platform.lower()}:{username.lower()}"
        return hashlib.sha256(data.encode()).hexdigest()


class DateParser:
    """Parse and format dates"""

    @staticmethod
    def parse_date(date_str: str) -> Optional[datetime]:
        """
        Parse date string to datetime

        Args:
            date_str: Date string

        Returns:
            datetime object or None
        """
        formats = [
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%d/%m/%Y',
            '%Y/%m/%d',
            '%B %d, %Y',
            '%b %d, %Y',
            '%m-%d-%Y',
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        return None

    @staticmethod
    def calculate_age(dob: str) -> Optional[int]:
        """
        Calculate age from date of birth

        Args:
            dob: Date of birth string

        Returns:
            Age in years
        """
        birth_date = DateParser.parse_date(dob)
        if birth_date:
            today = datetime.now()
            age = today.year - birth_date.year
            if today.month < birth_date.month or (
                today.month == birth_date.month and today.day < birth_date.day
            ):
                age -= 1
            return age
        return None

    @staticmethod
    def format_date(date: datetime, format: str = 'iso') -> str:
        """
        Format datetime to string

        Args:
            date: datetime object
            format: Format type (iso, us, readable)

        Returns:
            Formatted date string
        """
        if format == 'iso':
            return date.isoformat()
        elif format == 'us':
            return date.strftime('%m/%d/%Y')
        elif format == 'readable':
            return date.strftime('%B %d, %Y')
        else:
            return str(date)


class ScoreCalculator:
    """Calculate confidence and similarity scores"""

    @staticmethod
    def string_similarity(str1: str, str2: str) -> float:
        """
        Calculate similarity between two strings (Levenshtein-like)

        Args:
            str1: First string
            str2: Second string

        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not str1 or not str2:
            return 0.0

        str1 = str1.lower()
        str2 = str2.lower()

        if str1 == str2:
            return 1.0

        # Simple word overlap similarity
        words1 = set(str1.split())
        words2 = set(str2.split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union)

    @staticmethod
    def profile_match_score(profile1: Dict[str, Any], profile2: Dict[str, Any]) -> float:
        """
        Calculate match score between two profiles

        Args:
            profile1: First profile
            profile2: Second profile

        Returns:
            Match score (0.0 to 1.0)
        """
        score = 0.0
        weights = {
            'name': 0.3,
            'email': 0.2,
            'phone': 0.2,
            'address': 0.15,
            'dob': 0.15
        }

        # Name match
        if 'name' in profile1 and 'name' in profile2:
            name_sim = ScoreCalculator.string_similarity(
                profile1['name'],
                profile2['name']
            )
            score += name_sim * weights['name']

        # Email match
        if 'email' in profile1 and 'email' in profile2:
            if profile1['email'] == profile2['email']:
                score += weights['email']

        # Phone match
        if 'phone' in profile1 and 'phone' in profile2:
            phone1 = PhoneParser.normalize_phone(profile1['phone'])
            phone2 = PhoneParser.normalize_phone(profile2['phone'])
            if phone1 == phone2:
                score += weights['phone']

        # Address match
        if 'address' in profile1 and 'address' in profile2:
            addr_sim = ScoreCalculator.string_similarity(
                profile1['address'],
                profile2['address']
            )
            score += addr_sim * weights['address']

        # DOB match
        if 'dob' in profile1 and 'dob' in profile2:
            if profile1['dob'] == profile2['dob']:
                score += weights['dob']

        return min(score, 1.0)


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, calls_per_second: float = 1.0):
        """
        Initialize rate limiter

        Args:
            calls_per_second: Maximum calls per second
        """
        self.delay = 1.0 / calls_per_second
        self.last_call = datetime.now() - timedelta(seconds=self.delay)

    async def wait(self):
        """Wait if necessary to respect rate limit"""
        import asyncio

        now = datetime.now()
        time_since_last = (now - self.last_call).total_seconds()

        if time_since_last < self.delay:
            wait_time = self.delay - time_since_last
            await asyncio.sleep(wait_time)

        self.last_call = datetime.now()


class DataValidator:
    """Validate data quality and completeness"""

    @staticmethod
    def validate_person_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate person profile data

        Args:
            profile: Profile dictionary

        Returns:
            Validation results
        """
        issues = []
        warnings = []

        # Check required fields
        if not profile.get('name'):
            issues.append("Missing name")

        # Validate email
        if profile.get('email'):
            if not EmailParser.is_valid_email(profile['email']):
                warnings.append("Invalid email format")

        # Validate phone
        if profile.get('phone'):
            normalized = PhoneParser.normalize_phone(profile['phone'])
            if len(normalized) not in [10, 11]:
                warnings.append("Invalid phone number length")

        # Check data completeness
        completeness = 0
        total_fields = 10
        for field in ['name', 'email', 'phone', 'address', 'dob', 'city', 'state']:
            if profile.get(field):
                completeness += 1

        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'completeness': (completeness / total_fields) * 100
        }


if __name__ == "__main__":
    # Test utilities
    print("Testing Name Parser:")
    parsed = NameParser.parse_full_name("John Michael Doe Jr.")
    print(f"  Parsed: {parsed}")
    print(f"  Variations: {NameParser.generate_name_variations('John Doe')}")

    print("\nTesting Phone Parser:")
    print(f"  Normalized: {PhoneParser.normalize_phone('(555) 123-4567')}")
    print(f"  Formatted: {PhoneParser.format_phone('5551234567', 'national')}")

    print("\nTesting Email Parser:")
    print(f"  Valid: {EmailParser.is_valid_email('test@example.com')}")
    print(f"  Domain: {EmailParser.get_domain('test@example.com')}")

    print("\nTesting Address Parser:")
    addr = "123 Main Street, New York, NY 10001"
    print(f"  Parsed: {AddressParser.parse_address(addr)}")
    print(f"  Normalized: {AddressParser.normalize_address(addr)}")

    print("\nTesting Date Parser:")
    print(f"  Age: {DateParser.calculate_age('1990-01-01')}")

    print("\nTesting Score Calculator:")
    print(f"  Similarity: {ScoreCalculator.string_similarity('John Doe', 'John D.')}")
