"""
Phone Validator
Number format validation, country code verification, and type detection
"""

import re
import logging
from typing import Dict, Optional, Any, List
import phonenumbers
from phonenumbers import NumberParseException


class PhoneValidator:
    """
    Comprehensive phone number validation system
    """

    def __init__(self):
        """Initialize phone validator"""
        self.logger = self._setup_logging()

        # Common phone number patterns
        self.patterns = {
            'e164': re.compile(r'^\+[1-9]\d{1,14}$'),
            'us_domestic': re.compile(r'^(\+?1)?[\s.-]?\(?([0-9]{3})\)?[\s.-]?([0-9]{3})[\s.-]?([0-9]{4})$'),
            'international': re.compile(r'^\+?[1-9]\d{1,14}$'),
            'generic': re.compile(r'^[\d\s\-\(\)\+\.]+$')
        }

        # Invalid number patterns
        self.invalid_patterns = [
            re.compile(r'^0+$'),  # All zeros
            re.compile(r'^1+$'),  # All ones
            re.compile(r'^(\d)\1+$'),  # Repeating digits
            re.compile(r'^(123|234|345|456|567|678|789)+$'),  # Sequential
        ]

        # Known test/dummy numbers
        self.test_numbers = [
            '+15555550100',
            '+15555550101',
            '+15555550102',
            '+15555550123',
            '+15555551234',
        ]

        self.logger.info("Phone validator initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('PhoneValidator')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def validate(self, phone: str, region: Optional[str] = None) -> Dict[str, Any]:
        """
        Comprehensive phone number validation

        Args:
            phone: Phone number to validate
            region: Default region code (e.g., 'US', 'GB')

        Returns:
            Validation result dictionary
        """
        result = {
            'is_valid': False,
            'phone_number': phone,
            'normalized': None,
            'region': region,
            'validation_errors': [],
            'warnings': [],
            'checks': {
                'format_valid': False,
                'country_code_valid': False,
                'length_valid': False,
                'possible': False,
                'is_test_number': False,
                'is_suspicious': False
            },
            'metadata': {}
        }

        try:
            # Parse the phone number
            parsed = phonenumbers.parse(phone, region)

            # Basic format check
            result['checks']['format_valid'] = True
            result['normalized'] = phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.E164
            )

            # Check if possible (length, etc.)
            if phonenumbers.is_possible_number(parsed):
                result['checks']['possible'] = True
            else:
                result['validation_errors'].append('Number is not possible')

            # Check if valid (full validation)
            if phonenumbers.is_valid_number(parsed):
                result['checks']['length_valid'] = True
                result['checks']['country_code_valid'] = True
                result['is_valid'] = True
            else:
                result['validation_errors'].append('Number failed validation')

            # Extract metadata
            result['metadata'] = {
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'region': phonenumbers.region_code_for_number(parsed),
                'number_type': self._get_number_type(parsed),
                'timezone': phonenumbers.timezone.time_zones_for_number(parsed)
            }

            # Check for test numbers
            if result['normalized'] in self.test_numbers:
                result['checks']['is_test_number'] = True
                result['warnings'].append('This appears to be a test/dummy number')

            # Check for suspicious patterns
            if self._is_suspicious(result['normalized']):
                result['checks']['is_suspicious'] = True
                result['warnings'].append('Number has suspicious pattern')

        except NumberParseException as e:
            result['validation_errors'].append(f'Parse error: {e}')
            result['checks']['format_valid'] = False

        except Exception as e:
            self.logger.error(f"Validation error: {e}")
            result['validation_errors'].append(f'Validation error: {e}')

        return result

    def _get_number_type(self, parsed_number) -> str:
        """Get human-readable number type"""
        number_type = phonenumbers.number_type(parsed_number)

        type_map = {
            0: 'FIXED_LINE',
            1: 'MOBILE',
            2: 'FIXED_LINE_OR_MOBILE',
            3: 'TOLL_FREE',
            4: 'PREMIUM_RATE',
            5: 'SHARED_COST',
            6: 'VOIP',
            7: 'PERSONAL_NUMBER',
            8: 'PAGER',
            9: 'UAN',
            10: 'VOICEMAIL',
            -1: 'UNKNOWN'
        }

        return type_map.get(number_type, 'UNKNOWN')

    def _is_suspicious(self, phone: str) -> bool:
        """Check for suspicious number patterns"""
        # Remove + and country code for pattern checking
        digits = re.sub(r'[^\d]', '', phone)

        for pattern in self.invalid_patterns:
            if pattern.match(digits):
                return True

        return False

    def is_valid(self, phone: str, region: Optional[str] = None) -> bool:
        """
        Quick validation check

        Args:
            phone: Phone number
            region: Default region

        Returns:
            True if valid, False otherwise
        """
        result = self.validate(phone, region)
        return result['is_valid']

    def is_mobile(self, phone: str, region: Optional[str] = None) -> bool:
        """
        Check if number is mobile

        Args:
            phone: Phone number
            region: Default region

        Returns:
            True if mobile, False otherwise
        """
        try:
            parsed = phonenumbers.parse(phone, region)
            number_type = phonenumbers.number_type(parsed)
            return number_type == phonenumbers.PhoneNumberType.MOBILE
        except:
            return False

    def is_landline(self, phone: str, region: Optional[str] = None) -> bool:
        """
        Check if number is landline

        Args:
            phone: Phone number
            region: Default region

        Returns:
            True if landline, False otherwise
        """
        try:
            parsed = phonenumbers.parse(phone, region)
            number_type = phonenumbers.number_type(parsed)
            return number_type == phonenumbers.PhoneNumberType.FIXED_LINE
        except:
            return False

    def is_toll_free(self, phone: str, region: Optional[str] = None) -> bool:
        """Check if number is toll-free"""
        try:
            parsed = phonenumbers.parse(phone, region)
            number_type = phonenumbers.number_type(parsed)
            return number_type == phonenumbers.PhoneNumberType.TOLL_FREE
        except:
            return False

    def is_premium_rate(self, phone: str, region: Optional[str] = None) -> bool:
        """Check if number is premium rate"""
        try:
            parsed = phonenumbers.parse(phone, region)
            number_type = phonenumbers.number_type(parsed)
            return number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE
        except:
            return False

    def is_voip(self, phone: str, region: Optional[str] = None) -> bool:
        """Check if number is VoIP"""
        try:
            parsed = phonenumbers.parse(phone, region)
            number_type = phonenumbers.number_type(parsed)
            return number_type == phonenumbers.PhoneNumberType.VOIP
        except:
            return False

    def get_country_code(self, phone: str, region: Optional[str] = None) -> Optional[int]:
        """Extract country code"""
        try:
            parsed = phonenumbers.parse(phone, region)
            return parsed.country_code
        except:
            return None

    def get_region(self, phone: str, region: Optional[str] = None) -> Optional[str]:
        """Get region code"""
        try:
            parsed = phonenumbers.parse(phone, region)
            return phonenumbers.region_code_for_number(parsed)
        except:
            return None

    def format_number(self, phone: str, format_type: str = 'E164', region: Optional[str] = None) -> Optional[str]:
        """
        Format phone number

        Args:
            phone: Phone number
            format_type: Format type (E164, INTERNATIONAL, NATIONAL, RFC3966)
            region: Default region

        Returns:
            Formatted number or None
        """
        try:
            parsed = phonenumbers.parse(phone, region)

            format_map = {
                'E164': phonenumbers.PhoneNumberFormat.E164,
                'INTERNATIONAL': phonenumbers.PhoneNumberFormat.INTERNATIONAL,
                'NATIONAL': phonenumbers.PhoneNumberFormat.NATIONAL,
                'RFC3966': phonenumbers.PhoneNumberFormat.RFC3966
            }

            format_enum = format_map.get(format_type.upper(), phonenumbers.PhoneNumberFormat.E164)
            return phonenumbers.format_number(parsed, format_enum)

        except:
            return None

    def check_portability(self, phone: str, region: Optional[str] = None) -> Dict[str, Any]:
        """
        Check number portability status

        Args:
            phone: Phone number
            region: Default region

        Returns:
            Portability information
        """
        result = {
            'is_portable': False,
            'original_carrier': None,
            'current_carrier': None,
            'ported': False,
            'port_date': None
        }

        # Note: Actual portability checking requires carrier database access
        # This is a placeholder for the structure

        try:
            parsed = phonenumbers.parse(phone, region)

            # Check if number type supports portability
            number_type = phonenumbers.number_type(parsed)

            # Mobile numbers are typically portable
            if number_type == phonenumbers.PhoneNumberType.MOBILE:
                result['is_portable'] = True

            # Get carrier info (may not reflect portability)
            carrier_name = phonenumbers.carrier.name_for_number(parsed, 'en')
            result['current_carrier'] = carrier_name

        except Exception as e:
            self.logger.error(f"Portability check error: {e}")

        return result

    def batch_validate(self, phones: List[str], region: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Validate multiple phone numbers

        Args:
            phones: List of phone numbers
            region: Default region

        Returns:
            Dictionary mapping phone numbers to validation results
        """
        results = {}

        for phone in phones:
            results[phone] = self.validate(phone, region)

        return results

    def extract_numbers(self, text: str, region: Optional[str] = None) -> List[str]:
        """
        Extract phone numbers from text

        Args:
            text: Text containing phone numbers
            region: Default region for parsing

        Returns:
            List of extracted phone numbers in E.164 format
        """
        numbers = []

        try:
            # Use phonenumbers library to extract
            for match in phonenumbers.PhoneNumberMatcher(text, region):
                e164 = phonenumbers.format_number(
                    match.number,
                    phonenumbers.PhoneNumberFormat.E164
                )
                if e164 not in numbers:
                    numbers.append(e164)

        except Exception as e:
            self.logger.error(f"Error extracting numbers: {e}")

        return numbers


def main():
    """Example usage"""
    validator = PhoneValidator()

    # Validate a phone number
    result = validator.validate("+1-555-0123", "US")
    print("Validation result:")
    print(f"  Valid: {result['is_valid']}")
    print(f"  Normalized: {result['normalized']}")
    print(f"  Errors: {result['validation_errors']}")
    print(f"  Warnings: {result['warnings']}")

    # Quick checks
    phone = "+14155552671"
    print(f"\n{phone}:")
    print(f"  Valid: {validator.is_valid(phone)}")
    print(f"  Mobile: {validator.is_mobile(phone)}")
    print(f"  Region: {validator.get_region(phone)}")

    # Format number
    formatted = validator.format_number(phone, 'INTERNATIONAL')
    print(f"  International format: {formatted}")

    # Extract numbers from text
    text = "Call me at +1-415-555-2671 or (555) 123-4567"
    extracted = validator.extract_numbers(text, "US")
    print(f"\nExtracted numbers from text: {extracted}")

    # Batch validation
    numbers = ["+14155552671", "+442071234567", "+919876543210", "invalid"]
    batch_results = validator.batch_validate(numbers)
    print("\nBatch validation:")
    for num, res in batch_results.items():
        print(f"  {num}: {'Valid' if res['is_valid'] else 'Invalid'}")


if __name__ == "__main__":
    main()
